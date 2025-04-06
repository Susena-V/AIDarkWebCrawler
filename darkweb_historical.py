import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from statsmodels.tsa.arima.model import ARIMA
import networkx as nx
from database_manager import DatabaseManager

# --- Utility Functions ---
def load_synthetic_data(file_path):
    """Load synthetic attack data from a CSV file."""
    try:
        df = pd.read_csv(file_path)
        if "Timestamp" in df.columns:
            df["Timestamp"] = pd.to_datetime(df["Timestamp"])
            df["Date"] = df["Timestamp"].dt.date  # Extract date for aggregation
        return df
    except Exception as e:
        print(f"Error loading data: {e}")
        return None


class HistoryDashboard:
    def __init__(self):
        self.app = dash.Dash(__name__)
        self.db_manager = DatabaseManager()
        self.synthetic_data = load_synthetic_data("DarkWeb_attack_data.csv")
        self.create_dashboard()

    def fetch_all_data(self):
        """Fetch all data from the url_analysis table."""
        rows = self.db_manager.fetch_data()
        if not rows:
            print("No data available in the database.")
            return pd.DataFrame()

        # Define column names
        columns = ["id", "url", "email", "malware_links", "sentiment", "is_malicious", "timestamp"]
        df = pd.DataFrame(rows, columns=columns)

        # Process columns
        df["email_count"] = df["email"].apply(lambda x: len(eval(x)))
        df["malware_count"] = df["malware_links"].apply(lambda x: len(eval(x)))
        df["date"] = pd.to_datetime(df["timestamp"]).dt.date

        return df

    def analyze_attack_trends(self, df):
        """Aggregate attack data by date and visualize trends."""
        if df.empty:
            return {}
        trend_data = df.groupby("Date").size().reset_index(name="Attack Count")
        fig = px.line(trend_data, x="Date", y="Attack Count", title="Historical Attack Trends")
        return fig

    def predict_attack_frequency(self, df, steps=10):
        """Predict future attack frequencies using ARIMA."""
        if df.empty:
            return {}

        if "Date" in df.columns:
            df["Date"] = pd.to_datetime(df["Date"])  # Convert to datetime
            df = df.set_index("Date")  # Set 'Date' as the index

        ts = df.resample("D").size()

        # Fit ARIMA model
        model = ARIMA(ts, order=(5, 1, 0))
        model_fit = model.fit()

        # Make predictions
        forecast = model_fit.forecast(steps=steps)
        last_date = df.index[-1]
        forecast_dates = pd.date_range(start=last_date + pd.Timedelta(days=1), periods=steps, freq="D")
        forecast_df = pd.DataFrame({"Date": forecast_dates, "Predicted Attack Count": forecast})

        # Visualize predictions
        fig = px.line(forecast_df, x="Date", y="Predicted Attack Count", title="Predicted Attack Frequency")
        return fig

    def analyze_attack_types(self, df):
        """Analyze attack types and visualize their distribution."""
        if df.empty:
            return {}

        type_counts = df["Attack Type"].value_counts().reset_index()
        type_counts.columns = ["Attack Type", "Count"]
        fig = px.pie(type_counts, names="Attack Type", values="Count", title="Attack Type Distribution")
        return fig

    def generate_network_graph(self, df):
        """Generate a network graph showing relationships between sources and attack types."""
        if df.empty:
            return {}

        G = nx.DiGraph()

        for _, row in df.iterrows():
            source = row["Source"]
            attack_type = row["Attack Type"]
            G.add_node(source, type="source")
            G.add_node(attack_type, type="attack_type")
            G.add_edge(source, attack_type)

        pos = nx.spring_layout(G)

        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color="#888"),
            hoverinfo="none",
            mode="lines"
        )

        node_x = []
        node_y = []
        node_text = []
        node_color = []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(node)
            node_color.append("#FF4136" if G.nodes[node]["type"] == "source" else "#2ECC40")

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode="markers+text",
            text=node_text,
            textposition="top center",
            marker=dict(
                showscale=True,
                colorscale="YlGnBu",
                size=10,
                color=node_color
            ),
            hoverinfo="text"
        )

        fig = go.Figure(data=[edge_trace, node_trace],
                        layout=go.Layout(
                            title="Network Visualization of Attacks",
                            showlegend=False,
                            hovermode="closest",
                            margin=dict(b=20, l=5, r=5, t=40),
                            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                        ))
        return fig

    def create_dashboard(self):
        """Create the Dash app layout and callbacks."""
        self.app.layout = html.Div([
            html.H1("Unified Dark Web Threat Intelligence Dashboard"),
            dcc.Location(id="url", refresh=False),

            # Dropdown for filtering attack types
            dcc.Dropdown(
                id="attack-type-filter",
                options=[{"label": at, "value": at} for at in self.synthetic_data["Attack Type"].unique()],
                value=None,
                placeholder="Filter by Attack Type"
            ),

            # Historical Analysis Section
            html.Div([
                html.H2("Historical Analysis Dashboard"),
                dcc.Graph(id="historical-trends"),
                dcc.Graph(id="predicted-frequencies"),
                dcc.Graph(id="attack-types"),
                dcc.Graph(id="network-graph"),
            ]),

            # URL Analysis Section
            html.Div([
                html.H2("URL Analysis Dashboard"),
                dcc.Graph(id="sentiment-pie-chart"),
                dcc.Graph(id="pii-bar-chart"),
                dcc.Graph(id="malware-bar-chart"),
                dcc.Graph(id="trend-line-chart")
            ])
        ])

        @self.app.callback(
            [
                dash.dependencies.Output("historical-trends", "figure"),
                dash.dependencies.Output("predicted-frequencies", "figure"),
                dash.dependencies.Output("attack-types", "figure"),
                dash.dependencies.Output("network-graph", "figure"),
                dash.dependencies.Output("sentiment-pie-chart", "figure"),
                dash.dependencies.Output("pii-bar-chart", "figure"),
                dash.dependencies.Output("malware-bar-chart", "figure"),
                dash.dependencies.Output("trend-line-chart", "figure")
            ],
            [
                dash.dependencies.Input("attack-type-filter", "value"),
                dash.dependencies.Input("url", "search")
            ]
        )
        def update_dashboard(selected_type, _):
            # Fetch data
            db_data = self.fetch_all_data()
            synthetic_data = self.synthetic_data

            # Filter synthetic data
            filtered_synthetic_data = synthetic_data[synthetic_data["Attack Type"] == selected_type] if selected_type else synthetic_data

            # Generate historical analysis figures
            historical_trends = self.analyze_attack_trends(filtered_synthetic_data)
            predicted_frequencies = self.predict_attack_frequency(filtered_synthetic_data)
            attack_types = self.analyze_attack_types(filtered_synthetic_data)
            network_graph = self.generate_network_graph(filtered_synthetic_data)

            # Generate URL analysis figures
            sentiment_counts = db_data["sentiment"].value_counts().reset_index()
            sentiment_counts.columns = ["Sentiment", "Count"]
            sentiment_pie = px.pie(sentiment_counts, names="Sentiment", values="Count", title="Sentiment Distribution")

            pii_counts = db_data.groupby("url")["email_count"].sum().reset_index()
            pii_counts.columns = ["URL", "PII Count"]
            pii_bar = px.bar(pii_counts, x="URL", y="PII Count", title="PII Detected per URL")

            malware_counts = db_data.groupby("url")["malware_count"].sum().reset_index()
            malware_counts.columns = ["URL", "Malware Links Count"]
            malware_bar = px.bar(malware_counts, x="URL", y="Malware Links Count", title="Malware Links per URL")

            trend_data = db_data.groupby("date").size().reset_index(name="Count")
            trend_line = px.line(trend_data, x="date", y="Count", title="Threat Trends Over Time")

            return (
                historical_trends,
                predicted_frequencies,
                attack_types,
                network_graph,
                sentiment_pie,
                pii_bar,
                malware_bar,
                trend_line
            )

    def run(self):
        """Run the Dash app."""
        self.app.run_server(debug=True, port=8054)


if __name__ == "__main__":
    dashboard = HistoryDashboard()
    dashboard.run()