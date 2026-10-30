"""Schema-aware data cleaning hooks; implement after inspecting organiser CSVs."""
import pandas as pd

def inspect_frame(frame: pd.DataFrame) -> dict[str, object]:
    return {
        "rows": int(len(frame)),
        "columns": int(len(frame.columns)),
        "column_names": [str(c) for c in frame.columns],
        "missing_by_column": frame.isna().sum().astype(int).to_dict(),
        "duplicate_rows": int(frame.duplicated().sum()),
    }

def clean_training_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """TODO: implement using actual organiser schema and training data only."""
    raise NotImplementedError("Awaiting organiser dataset and exact label mapping.")
