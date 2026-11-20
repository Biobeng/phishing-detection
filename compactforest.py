"""
A Random Forest stored as plain arrays.

The link Random Forest has 150 full-depth trees, about 2.4 million nodes. Kept
as a scikit-learn object it needs roughly 400 MB of memory once loaded, which
is more than a small hosting plan allows. Here the same trees are kept as five
flat arrays and walked with NumPy. The splits, thresholds and leaf values are
copied exactly, so the scores match scikit-learn's predict_proba.
"""
import numpy as np


class CompactForest:
    def __init__(self, path):
        d = np.load(path)
        self.left = d["left"]
        self.right = d["right"]
        self.feature = d["feature"]
        self.threshold = d["threshold"]
        self.proba = d["proba"]
        self.roots = d["roots"]

    def predict_proba(self, X):
        """Same shape as scikit-learn: one row per input, columns for class 0 and 1."""
        X = np.asarray(X, dtype=np.float32)   # scikit-learn's trees compare float32 inputs
        out = np.empty((X.shape[0], 2))
        for i, row in enumerate(X):
            node = self.roots.copy()
            while True:
                left = self.left[node]
                inner = left != -1
                if not inner.any():
                    break
                go_left = row[self.feature[node]] <= self.threshold[node]
                node = np.where(inner, np.where(go_left, left, self.right[node]), node)
            p = self.proba[node].mean()
            out[i] = (1.0 - p, p)
        return out


def compact(forest, path):
    """Write a fitted RandomForestClassifier out in the compact form."""
    one = list(forest.classes_).index(1)
    left, right, feat, thr, prob, roots = [], [], [], [], [], []
    offset = 0
    for est in forest.estimators_:
        t = est.tree_
        roots.append(offset)
        l = t.children_left.astype(np.int64)
        r = t.children_right.astype(np.int64)
        left.append(np.where(l == -1, -1, l + offset))
        right.append(np.where(r == -1, -1, r + offset))
        feat.append(t.feature)
        thr.append(t.threshold)
        v = t.value[:, 0, :]
        prob.append(v[:, one] / v.sum(axis=1))
        offset += t.node_count
    np.savez_compressed(path,
             left=np.concatenate(left).astype(np.int32),
             right=np.concatenate(right).astype(np.int32),
             feature=np.clip(np.concatenate(feat), 0, None).astype(np.int16),
             threshold=np.concatenate(thr).astype(np.float64),
             proba=np.concatenate(prob).astype(np.float64),
             roots=np.array(roots, dtype=np.int64))
