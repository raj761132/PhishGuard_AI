from datasets import load_dataset
from pathlib import Path
import re
import pandas as pd

def extract_url_from_text(text):
    if not isinstance(text, str):
        return None
    match = re.search(r"https?://[^\s\"'>]+", text)
    return match.group(0) if match else None

def load_url_dataset():
    base_dir = Path(__file__).resolve().parents[2]
    json_path = base_dir / "dataset" / "hf_phishing" / "combined_reduced.json"

    dataset = load_dataset(
        "json",
        data_files={"train": str(json_path)}
    )

    df = dataset["train"].to_pandas()

    # 🔽 FILTERING HAPPENS HERE 🔽
    df["url"] = df["text"].apply(extract_url_from_text)
    df = df.dropna(subset=["url"])

    # Keep only required columns
    df = df[["url", "label"]]

    return df
