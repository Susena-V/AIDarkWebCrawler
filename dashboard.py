import dash
from dash import dcc, html, dash_table
import pandas as pd
import psycopg2
import plotly.express as px
import dash_bootstrap_components as dbc

# Function to fetch data from PostgreSQL
def fetch_data():
    try:
        conn = psycopg2.connect(
            dbname="threat_analysis",
            user="susenavenkateshnathan",  # Replace with your PostgreSQL username
            password="1845",  # Replace with your PostgreSQL password
            host="localhost",
            port="5432"
        )
        query = "SELECT id, url, risk_level, analyzed_at FROM analysis_results;"
        df = pd.read_sql_query(query, conn)
        conn.close()
        df['analyzed_at'] = pd.to_datetime(df['analyzed_at'])
        df['date'] = df['analyzed_at'].dt.date  # Extract only the date for trend visualization
        return df
    except Exception as e:
        print(f"Error: {e}")
        return pd.DataFrame(columns=['id', 'url', 'risk_level', 'analyzed_at', 'date'])

# Load Data
df = fetch_data()
color_map = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}

# Create Dash App
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])

app.layout = dbc.Container([
    dbc.Row([
        dbc.Col(html.H1("Threat Analysis Dashboard", className="text-center mb-4 text-white"), width=12)
    ]),

    # Risk Level Distribution & Trend of URLs Analyzed Over Time
    dbc.Row([
        dbc.Col(dcc.Graph(
            id='risk-level-chart',
            figure=px.bar(df, x='risk_level', title="Risk Level Distribution", 
                          color='risk_level', text_auto=False, color_discrete_map=color_map).update_layout(
                xaxis_title="Risk Level", yaxis_title="Count", template="plotly_dark", paper_bgcolor="#121212", plot_bgcolor="#121212")
        ), width=6),
        
        dbc.Col(dcc.Graph(
            id='urls-time-trend',
            figure=px.line(df.groupby('date').size().reset_index(name='count'), 
                           x='date', y='count', title="Trend of URLs Analyzed Over Time").update_layout(
                xaxis_title="Date", yaxis_title="Count", template="plotly_dark", paper_bgcolor="#121212", plot_bgcolor="#121212")
        ), width=6)
    ]),
    
    # URLs Analyzed Over Time (Scatter Plot - Wide)
    dbc.Row([
        dbc.Col(dcc.Graph(
            id='urls-over-time',
            figure=px.scatter(df, x='analyzed_at', y='url', color='risk_level', 
                              title="URLs Analyzed Over Time", color_discrete_map=color_map).update_layout(
                xaxis_title="Timestamp", yaxis_title="URL", template="plotly_dark", paper_bgcolor="#121212", plot_bgcolor="#121212")
        ), width=12)
    ])
], fluid=True, style={"backgroundColor": "#121212", "color": "white"})

if __name__ == '__main__':
    app.run(debug=True, port=5002)