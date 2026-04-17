"""数据集完整性检查脚本

检查当前 BCCC-CSE-CIC-IDS-2018 数据集是子集（示例）还是全量，
并提示缺失的文件、下载方式和下一步操作。

用法:
    python check_dataset.py
"""

import os
import sys

# Windows控制台使用GBK, 强制UTF-8避免中文错误
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

DATASET_DIR = "data/数据集BCCC-CSE-CIC-IDS-2018"
RAW_DIR = "data/raw"

# 期望的外层ZIP文件 -> 内部包含的攻击类别子集
EXPECTED_ZIPS = {
    "Wednesday_14_02_2018.zip": ["benign", "BF_FTP", "BF_SSH"],
    "Thursday_15_02_2018.zip": ["benign", "DoS_Golden_Eye", "DoS_Slowloris"],
    "Friday-16-02-2018.zip": ["benign(x3)", "dos_hulk(x2)", "dos_slowhttp(x2)"],
    "Tuesday_20_02_2018.zip": ["benign", "loic_http"],
    "Wednesday_21_02_2018.zip": ["benign(x4)", "hoic(x2)"],
    "Thursday-22-02-2018.zip": ["benign", "BF_web", "BF_XSS", "SQL_Injection"],
    "Friday-23-02-2018.zip": ["benign", "BF_web", "BF_XSS", "SQL_Injection"],
    "Wednesday-28-02-2018.zip": ["benign"],
    "Thursday-01-03-2018.zip": ["benign", "infiltration"],
    "Friday-02-03-2018.zip": ["benign", "bot"],
}

SAMPLE_CSV_NAME = "cic_ids_2018_sampled.csv"


def human_size(num_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num_bytes < 1024:
            return f"{num_bytes:.1f}{unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f}TB"


def check_outer_zips():
    """检查外层ZIP存在情况"""
    print(f"\n[1/3] 外层ZIP检查 ({DATASET_DIR})")
    print("-" * 60)

    if not os.path.exists(DATASET_DIR):
        print(f"  目录不存在")
        return [], list(EXPECTED_ZIPS.keys())

    present, missing = [], []
    for zip_name, contents in EXPECTED_ZIPS.items():
        path = os.path.join(DATASET_DIR, zip_name)
        if os.path.exists(path):
            size = os.path.getsize(path)
            present.append((zip_name, size))
            print(f"  [OK]   {zip_name:<32s} {human_size(size):>10s}  "
                  f"[{', '.join(contents)}]")
        else:
            missing.append(zip_name)
            print(f"  [MISS] {zip_name:<32s} {'-':>10s}  "
                  f"[{', '.join(contents)}]")
    return present, missing


def check_extracted_csvs():
    """检查已提取CSV"""
    print(f"\n[2/3] 已提取CSV检查 ({RAW_DIR})")
    print("-" * 60)

    if not os.path.exists(RAW_DIR):
        print("  目录不存在")
        return [], False

    csv_files = sorted(f for f in os.listdir(RAW_DIR) if f.endswith(".csv"))
    sampled_exists = SAMPLE_CSV_NAME in csv_files

    raw_csvs = [f for f in csv_files if f != SAMPLE_CSV_NAME]

    if not csv_files:
        print("  (无CSV文件)")
    else:
        for f in csv_files:
            size = os.path.getsize(os.path.join(RAW_DIR, f))
            marker = "[SAMPLED]" if f == SAMPLE_CSV_NAME else "[RAW]    "
            print(f"  {marker} {f:<45s} {human_size(size):>10s}")

    return raw_csvs, sampled_exists


def classify_status(
    n_present: int, n_total: int, n_csv: int, sampled_exists: bool
) -> str:
    """判断当前数据集状态"""
    if n_present == 0:
        return "NOT_DOWNLOADED"
    if n_present < n_total:
        return "PARTIAL_ZIP"
    # 全量ZIP都在
    if n_csv == 0:
        return "ZIP_ONLY"
    if n_csv < 15:
        return "SAMPLE_EXTRACTED"
    return "FULL_EXTRACTED"


def print_download_instructions():
    print()
    print("下载 BCCC-CSE-CIC-IDS-2018 数据集:")
    print()
    print("  方法1 - 官方CIC站点 (原始PCAP):")
    print("    https://www.unb.ca/cic/datasets/ids-2018.html")
    print()
    print("  方法2 - BCCC 重处理版本 (本项目使用, 推荐):")
    print("    https://www.unb.ca/cic/datasets/")
    print("    查找 BCCC-CSE-CIC-IDS-2018 即可")
    print()
    print("  方法3 - 使用AWS CLI (CIC官方提供的S3镜像):")
    print("    aws s3 sync --no-sign-request \\")
    print("      s3://cse-cic-ids2018/Processed-Traffic-Data-for-ML-Algorithms/ \\")
    print("      ./data/")
    print()
    print(f"  下载完成后，将所有ZIP文件放到: {DATASET_DIR}/")


def print_next_steps(status: str, missing: list, sampled_exists: bool):
    print()
    print("=" * 60)
    print("下一步操作建议")
    print("=" * 60)

    if status == "NOT_DOWNLOADED":
        print("\n[状态] 尚未下载数据集")
        print_download_instructions()
        return

    if status == "PARTIAL_ZIP":
        print(f"\n[状态] 部分ZIP缺失 ({len(missing)} 个):")
        for z in missing:
            print(f"  - {z}")
        print_download_instructions()
        print("\n可以使用现有部分ZIP进行测试:")
        print("  python prepare_data.py           # 提取代表性子集")
        return

    if status == "ZIP_ONLY":
        print("\n[状态] 全量ZIP已就绪, 尚未提取CSV")
        print()
        print("选项A - 提取代表性子集 (快速测试, 约5分钟):")
        print("  python prepare_data.py")
        print()
        print("选项B - 提取全量数据集 (完整实验, 约需100GB磁盘空间):")
        print("  python prepare_data.py --full")
        return

    if status == "SAMPLE_EXTRACTED":
        print("\n[状态] 已提取代表性子集CSV")
        if not sampled_exists:
            print("\n生成训练采样数据:")
            print("  python sample_data.py")
        else:
            print(f"  采样数据: {SAMPLE_CSV_NAME}")
        print()
        print("如需完整实验, 提取全量数据:")
        print("  python prepare_data.py --full")
        return

    if status == "FULL_EXTRACTED":
        print("\n[状态] 全量数据集已提取")
        if not sampled_exists:
            print("\n生成训练采样数据 (从全量采样):")
            print("  python sample_data.py --full-source")
        else:
            print(f"  采样数据: {SAMPLE_CSV_NAME}")


def main():
    print("=" * 60)
    print("BCCC-CSE-CIC-IDS-2018 数据集完整性检查")
    print("=" * 60)

    present, missing = check_outer_zips()
    raw_csvs, sampled_exists = check_extracted_csvs()

    status = classify_status(
        n_present=len(present),
        n_total=len(EXPECTED_ZIPS),
        n_csv=len(raw_csvs),
        sampled_exists=sampled_exists,
    )

    print(f"\n[3/3] 状态汇总")
    print("-" * 60)
    print(f"  外层ZIP:    {len(present)}/{len(EXPECTED_ZIPS)}")
    print(f"  已提取CSV:  {len(raw_csvs)}")
    print(f"  采样数据:   {'存在' if sampled_exists else '未生成'}")
    print(f"  整体状态:   {status}")

    print_next_steps(status, missing, sampled_exists)
    print()

    # 以状态码返回（方便在脚本中判断）
    return 0 if status in ("SAMPLE_EXTRACTED", "FULL_EXTRACTED") else 1


if __name__ == "__main__":
    sys.exit(main())
