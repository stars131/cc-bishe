"""数据准备脚本 - 从CIC-IDS-2018嵌套ZIP中提取CSV

默认模式 (代表性子集, 约5分钟):
    python prepare_data.py

全量模式 (所有攻击类型+正常流量, 耗时较长):
    python prepare_data.py --full

单文件模式 (只处理指定的外层ZIP):
    python prepare_data.py --only Wednesday_14_02_2018.zip
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Windows控制台编码修正
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


DATASET_DIR = "data/数据集BCCC-CSE-CIC-IDS-2018"
OUTPUT_DIR = "data/raw"

# 代表性子集 (覆盖多种攻击类型, 避免数据过大)
SAMPLE_ZIPS = [
    "Wednesday_14_02_2018.zip",   # Brute Force FTP/SSH
    "Thursday_15_02_2018.zip",    # DoS GoldenEye/Slowloris
    "Friday-23-02-2018.zip",      # BF Web/XSS/SQL Injection
    "Friday-02-03-2018.zip",      # Bot
]

# 全量数据集 (全部10个外层ZIP)
ALL_ZIPS = [
    "Wednesday_14_02_2018.zip",   # Brute Force FTP/SSH
    "Thursday_15_02_2018.zip",    # DoS GoldenEye/Slowloris
    "Friday-16-02-2018.zip",      # DoS Hulk / DoS SlowHTTPTest
    "Tuesday_20_02_2018.zip",     # DDoS LOIC-HTTP
    "Wednesday_21_02_2018.zip",   # DDoS HOIC
    "Thursday-22-02-2018.zip",    # BF Web/XSS/SQL Injection
    "Friday-23-02-2018.zip",      # BF Web/XSS/SQL Injection
    "Wednesday-28-02-2018.zip",   # Benign only
    "Thursday-01-03-2018.zip",    # Infiltration
    "Friday-02-03-2018.zip",      # Bot
]


def extract_inner_zip_with_powershell(
    inner_zip_path: str, output_csv_dir: str
) -> list:
    """使用PowerShell解压内层ZIP (绕过Python对Deflate64的不支持)

    Returns:
        成功提取的CSV文件路径列表
    """
    saved = []
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            [
                "powershell", "-Command",
                f"Expand-Archive -Path '{inner_zip_path}' "
                f"-DestinationPath '{tmpdir}' -Force",
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            err = (result.stderr or "").strip().splitlines()
            first_err = err[0] if err else "unknown"
            print(f"    [SKIP] PowerShell解压失败: {first_err[:100]}")
            return saved

        for root, _, files in os.walk(tmpdir):
            for f in files:
                if not f.endswith(".csv"):
                    continue
                src = os.path.join(root, f)
                dst = os.path.join(output_csv_dir, f)
                if os.path.exists(dst):
                    print(f"    [SKIP] 已存在: {f}")
                    continue
                try:
                    shutil.copy2(src, dst)
                    size_mb = os.path.getsize(dst) / 1024 / 1024
                    print(f"    [SAVE] {f} ({size_mb:.1f}MB)")
                    saved.append(dst)
                except Exception as e:
                    print(f"    [ERR]  复制 {f} 失败: {e}")
    return saved


def process_outer_zip(outer_zip_path: str, output_dir: str) -> int:
    """处理外层ZIP: 解压 -> 提取每个内层ZIP的CSV"""
    if not os.path.exists(outer_zip_path):
        print(f"  [MISS] 未找到: {os.path.basename(outer_zip_path)}")
        return 0

    count = 0
    with tempfile.TemporaryDirectory() as tmpdir:
        # 解压外层ZIP
        result = subprocess.run(
            [
                "powershell", "-Command",
                f"Expand-Archive -Path '{outer_zip_path}' "
                f"-DestinationPath '{tmpdir}' -Force",
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"  [ERR] 外层解压失败")
            return 0

        # 递归寻找内层ZIP
        inner_zips = []
        for root, _, files in os.walk(tmpdir):
            for f in files:
                if f.endswith(".zip"):
                    inner_zips.append(os.path.join(root, f))

        print(f"  找到 {len(inner_zips)} 个内层ZIP")
        for inner in sorted(inner_zips):
            print(f"  解压: {os.path.basename(inner)}")
            saved = extract_inner_zip_with_powershell(inner, output_dir)
            count += len(saved)

    return count


def main():
    parser = argparse.ArgumentParser(
        description="从CIC-IDS-2018嵌套ZIP中提取CSV文件"
    )
    parser.add_argument(
        "--full", action="store_true",
        help="提取全量数据集 (10个外层ZIP, 耗时较长, 需约100GB磁盘空间)",
    )
    parser.add_argument(
        "--only", type=str, default=None,
        help="只处理指定的外层ZIP文件名",
    )
    parser.add_argument(
        "--output", type=str, default=OUTPUT_DIR,
        help=f"CSV输出目录 (默认: {OUTPUT_DIR})",
    )
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    if args.only:
        target_zips = [args.only]
        mode = f"单文件模式: {args.only}"
    elif args.full:
        target_zips = ALL_ZIPS
        mode = f"全量模式 ({len(ALL_ZIPS)} 个外层ZIP)"
    else:
        target_zips = SAMPLE_ZIPS
        mode = f"代表性子集模式 ({len(SAMPLE_ZIPS)} 个外层ZIP)"

    print("=" * 60)
    print(f"CIC-IDS-2018 数据提取 - {mode}")
    print("=" * 60)

    total_extracted = 0
    for zip_name in target_zips:
        zip_path = os.path.join(DATASET_DIR, zip_name)
        print(f"\n处理: {zip_name}")
        print("-" * 60)
        total_extracted += process_outer_zip(zip_path, args.output)

    print()
    print("=" * 60)
    print(f"提取完成: 共 {total_extracted} 个CSV文件保存至 {args.output}/")
    print("=" * 60)
    print()
    print("下一步: 生成训练采样数据")
    print("  python sample_data.py")


if __name__ == "__main__":
    main()
