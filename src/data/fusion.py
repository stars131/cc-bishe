"""特征级融合模块 - 支持Cross-Attention与多种消融融合方式"""

import torch
import torch.nn as nn
import math


class CrossAttention(nn.Module):
    """交叉注意力模块：一个模态作为Query，另一个作为Key/Value"""

    def __init__(self, d_model: int, nhead: int, dropout: float = 0.1):
        super().__init__()
        self.multihead_attn = nn.MultiheadAttention(
            embed_dim=d_model, num_heads=nhead, dropout=dropout, batch_first=True
        )
        self.norm = nn.LayerNorm(d_model)
        self.dropout = nn.Dropout(dropout)

    def forward(
        self, query: torch.Tensor, key_value: torch.Tensor
    ) -> torch.Tensor:
        """
        Args:
            query: (batch, seq_len_q, d_model)
            key_value: (batch, seq_len_kv, d_model)

        Returns:
            (batch, seq_len_q, d_model)
        """
        attn_out, _ = self.multihead_attn(query, key_value, key_value)
        out = self.norm(query + self.dropout(attn_out))
        return out


class MultiModalFusion(nn.Module):
    """多模态特征融合模块

    流量特征和日志特征分别投影到d_model维度，
    通过双向Cross-Attention融合后拼接并投影。
    """

    def __init__(
        self,
        traffic_dim: int,
        log_dim: int,
        d_model: int = 128,
        nhead: int = 8,
        dropout: float = 0.1,
        fusion_strategy: str = "cross_attention",
    ):
        super().__init__()
        valid_strategies = {
            "cross_attention",
            "concat",
            "traffic_only",
            "log_only",
        }
        if fusion_strategy not in valid_strategies:
            raise ValueError(f"不支持的融合策略: {fusion_strategy}")
        self.fusion_strategy = fusion_strategy

        # 特征投影层
        self.traffic_proj = nn.Sequential(
            nn.Linear(traffic_dim, d_model),
            nn.ReLU(),
            nn.Dropout(dropout),
        )
        self.log_proj = nn.Sequential(
            nn.Linear(log_dim, d_model),
            nn.ReLU(),
            nn.Dropout(dropout),
        )

        if fusion_strategy in {"cross_attention", "concat"}:
            self.fusion_proj = nn.Sequential(
                nn.Linear(d_model * 2, d_model),
                nn.ReLU(),
                nn.Dropout(dropout),
            )

        if fusion_strategy == "cross_attention":
            # 位置编码（可学习）
            self.traffic_pos = nn.Parameter(torch.randn(1, 1, d_model) * 0.02)
            self.log_pos = nn.Parameter(torch.randn(1, 1, d_model) * 0.02)

            # 双向Cross-Attention
            self.traffic_to_log_attn = CrossAttention(d_model, nhead, dropout)
            self.log_to_traffic_attn = CrossAttention(d_model, nhead, dropout)

    def forward(
        self, traffic: torch.Tensor, log: torch.Tensor
    ) -> torch.Tensor:
        """
        Args:
            traffic: (batch, traffic_dim) 流量特征
            log: (batch, log_dim) 日志特征

        Returns:
            (batch, d_model) 融合后的特征向量
        """
        traffic_proj = self.traffic_proj(traffic)
        log_proj = self.log_proj(log)

        if self.fusion_strategy == "traffic_only":
            return traffic_proj

        if self.fusion_strategy == "log_only":
            return log_proj

        if self.fusion_strategy == "concat":
            fused = torch.cat([traffic_proj, log_proj], dim=-1)
            return self.fusion_proj(fused)

        # cross_attention
        traffic_emb = traffic_proj.unsqueeze(1) + self.traffic_pos
        log_emb = log_proj.unsqueeze(1) + self.log_pos

        traffic_attended = self.traffic_to_log_attn(traffic_emb, log_emb)
        log_attended = self.log_to_traffic_attn(log_emb, traffic_emb)

        traffic_out = traffic_attended.squeeze(1)
        log_out = log_attended.squeeze(1)
        fused = torch.cat([traffic_out, log_out], dim=-1)
        return self.fusion_proj(fused)
