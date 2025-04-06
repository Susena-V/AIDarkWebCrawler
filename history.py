import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
from statsmodels.tsa.arima.model import ARIMA

# Load dataset
df = pd.read_csv("DarkWeb_attack_data.csv")

# Convert 'Date' column to datetime
df['Date'] = pd.to_datetime(df['Date'])

# Aggregate attacks per day
attack_counts = df.groupby("Date").size().asfreq("D", fill_value=0)

# Train ARIMA Model
model = ARIMA(attack_counts, order=(5, 1, 0))
model_fit = model.fit()

# Predict for next 30 days
future_dates = pd.date_range(start=attack_counts.index[-1], periods=30, freq="D")
predictions = model_fit.forecast(steps=30)
forecast_df = pd.DataFrame({"Date": future_dates, "Predicted Attacks": predictions})

# Initialize Dash app
app = dash.Dash(__name__)

# Layout
app.layout = html.Div([
    html.H1("Dark Web Attack Analysis Dashboard", style={'textAlign': 'center', 'color': '#4CAF50'}),

    html.Div([
        html.Div([dcc.Graph(id="attack-trends")], className="six columns"),
        html.Div([dcc.Graph(id="attack-prediction")], className="six columns"),
    ], className="row"),

    html.Div([
        html.Div([dcc.Graph(id="severity-distribution")], className="six columns"),
        html.Div([dcc.Graph(id="attack-frequency")], className="six columns"),
    ], className="row"),

    html.Div([
        dcc.Graph(id="attack-network")
    ], className="twelve columns"),
])

# Callbacks
@app.callback(
    Output("attack-trends", "figure"),
    Input("attack-trends", "id")
)
def update_attack_trends(_):
    trend_data = df.groupby("Date").size().reset_index(name="Count")
    fig = px.line(trend_data, x="Date", y="Count", title="Attack Trends Over Time", color_discrete_sequence=['#007bff'])
    fig.update_layout(template="plotly_dark")
    return fig

@app.callback(
    Output("severity-distribution", "figure"),
    Input("severity-distribution", "id")
)
def update_severity_distribution(_):
    fig = px.pie(df, names="Severity", title="Severity Distribution", color_discrete_sequence=px.colors.sequential.RdBu)
    fig.update_layout(template="plotly_dark")
    return fig

@app.callback(
    Output("attack-frequency", "figure"),
    Input("attack-frequency", "id")
)
def update_attack_frequency(_):
    attack_counts = df["Attack Type"].value_counts().reset_index()
    attack_counts.columns = ["Attack Type", "Count"]
    fig = px.bar(attack_counts, x="Attack Type", y="Count", title="Attack Type Frequency", color='Count', color_continuous_scale='Viridis')
    fig.update_layout(template="plotly_dark")
    return fig

@app.callback(
    Output("attack-network", "figure"),
    Input("attack-network", "id")
)
def update_attack_network(_):
    G = nx.Graph()
    
    for _, row in df.iterrows():
        if row["Source"] not in G:
            G.add_node(row["Source"], size=row["Severity"])
        if row["Attack Type"] not in G:
            G.add_node(row["Attack Type"], size=5)
        G.add_edge(row["Source"], row["Attack Type"])

    pos = nx.spring_layout(G, seed=42)
    edge_trace = go.Scatter(
        x=[], y=[], line=dict(width=0.5, color='#888'), hoverinfo='none', mode='lines'
    )

    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_trace['x'] += (x0, x1, None)
        edge_trace['y'] += (y0, y1, None)

    node_trace = go.Scatter(
        x=[], y=[], text=[], mode='markers', hoverinfo='text',
        marker=dict(size=[], color=[], line=dict(width=2))
    )

    for node in G.nodes():
        x, y = pos[node]
        node_trace['x'] += (x,)
        node_trace['y'] += (y,)
        node_trace['text'] += (node,)
        node_trace['marker']['size'] += (G.nodes[node].get('size', 5) * 2,)
        node_trace['marker']['color'] += ('#4CAF50' if node in df['Source'].values else '#007bff',)

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(title='Source-wise Attack Network', showlegend=False, template="plotly_dark")
    return fig

@app.callback(
    Output("attack-prediction", "figure"),
    Input("attack-prediction", "id")
)
def update_attack_prediction(_):
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=attack_counts.index, y=attack_counts, mode="lines", name="Actual Attacks", line=dict(color="#4CAF50")))
    fig.add_trace(go.Scatter(x=forecast_df["Date"], y=forecast_df["Predicted Attacks"], mode="lines", name="Predicted Attacks", line=dict(dash="dash", color="red")))
    fig.update_layout(title="ARIMA Prediction: Future Attack Trends", xaxis_title="Date", yaxis_title="Attack Count", template="plotly_dark")
    return fig

# Run app
if __name__ == "__main__":
    app.run(debug=True)
