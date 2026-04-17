"""从已提取的CSV中采样, 创建可用于训练的平衡数据集

默认模式 (快速采样, 每大文件仅读取前5万行):
    python sample_data.py

全量采样模式 (读取所有数据, 再从中分层采样):
    python sample_data.py --full-source

自定义每类上限:
    python sample_data.py --max-per-class 30000
"""

import argparse
import os
import sys
import pandas as pd

# Windows控制台编码修正
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


RAW_DIR = "data/raw"
OUTPUT = "data/raw/cic_ids_2018_sampled.csv"

# 每类默认最大采样数
DEFAULT_MAX_PER_CLASS = 10000

# 快速采样模式下, 对大文件的预读行数上限
QUICK_MODE_ROW_LIMIT = 50000

# 判定"大文件"的阈值 (快速模式下仅对大文件预读前N行)
LARGE_FILE_MB_THRESHOLD = 100


def read_csv_files(csv_files: list, full_source: bool) -> pd.DataFrame:
    """读取CSV文件, 支持快速采样和全量读取两种模式"""
    dfs = []
    for f in sorted(csv_files):
        path = os.path.join(RAW_DIR, f)
        size_mb = os.path.getsize(path) / 1024 / 1024
        print(f"读取: {f} ({size_mb:.0f}MB)")

        nrows = None
        if not full_source and size_mb > LARGE_FILE_MB_THRESHOLD:
            nrows = QUICK_MODE_ROW_LIMIT
            print(f"  [快速模式] 仅读取前{nrows}行")

        df = pd.read_csv(path, low_memory=False, nrows=nrows)
        print(f"  行数: {len(df)}, 标签: {df['label'].unique()}")
        dfs.append(df)

    return pd.concat(dfs, ignore_index=True)


def main():
    parser = argparse.ArgumentParser(description="生成平衡采样训练数据")
    parser.add_argument(
        "--full-source", action="store_true",
        help="读取全量CSV后再采样 (适用于已执行 prepare_data.py --full)",
    )
    parser.add_argument(
        "--max-per-class", type=int, default=DEFAULT_MAX_PER_CLASS,
        help=f"每类最大采样数 (默认: {DEFAULT_MAX_PER_CLASS})",
    )
    parser.add_argument(
        "--output", type=str, default=OUTPUT,
        help=f"输出CSV路径 (默认: {OUTPUT})",
    )
    args = parser.parse_args()

    if not os.path.exists(RAW_DIR):
        print(f"错误: 未找到 {RAW_DIR} 目录, 请先运行 prepare_data.py")
        sys.exit(1)

    csv_files = [
        f for f in os.listdir(RAW_DIR)
        if f.endswith(".csv") and "sampled" not in f
    ]
    if not csv_files:
        print(f"错误: {RAW_DIR} 中无可用CSV, 请先运行 prepare_data.py")
        sys.exit(1)

    mode = "全量" if args.full_source else "快速"
    print(f"=" * 60)
    print(f"采样模式: {mode} | 每类上限: {args.max_per_class}")
    print(f"=" * 60)

    data = read_csv_files(csv_files, args.full_source)
    print(f"\n合并后总数据: {data.shape}")
    print(f"原始标签分布:\n{data['label'].value_counts()}\n")

    sampled = []
    for label, group in data.groupby("label"):
        n = min(len(group), args.max_per_class)
        s = group.sample(n=n, random_state=42)
        sampled.append(s)
        print(f"  {label:20s}: {len(group):>8d} -> {n}")

    result = (
        pd.concat(sampled)
        .sample(frac=1, random_state=42)
        .reset_index(drop=True)
    )
    result.to_csv(args.output, index=False)

    print(f"\n保存至: {args.output}")
    print(f"最终: {result.shape}")
    print(f"标签分布:\n{result['label'].value_counts()}")


if __name__ == "__main__":
    main()
