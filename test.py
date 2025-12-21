from ml.train.load_dataset import load_url_dataset
from ml.features.url_features import extract_features



df = load_url_dataset()

print("✅ Dataset loaded successfully")
print("Shape:", df.shape)
print("Columns:", df.columns.tolist())
print(df.head())
print(extract_features("http://online0mgeving.ga/triodos/"))
