"""XGB-IDI classification using the shared experiment configuration."""
from xgboost import XGBClassifier


def fit_classifier(features, labels, config, seed):
    return XGBClassifier(**config, random_state=seed).fit(features, labels)
