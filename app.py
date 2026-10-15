
import re
from collections import Counter

import pandas as pd
import plotly.express as px
import streamlit as st


# Configuração da página
st.set_page_config(
    page_title="LogSentinel",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ LogSentinel")
st.caption("Dashboard de análise de logs de autenticação SSH")


# Dados fictícios para demonstrar o funcionamento
SAMPLE_LOGS = """Oct 10 10:01:02 server sshd[101]: Failed password for invalid user admin from 192.168.1.10 port 2222 ssh2
Oct 10 10:01:05 server sshd[102]: Failed password for root from 192.168.1.10 port 2223 ssh2
Oct 10 10:01:08 server sshd[103]: Failed password for test from 192.168.1.10 port 2224 ssh2
Oct 10 10:02:00 server sshd[104]: Accepted password for gustavo from 192.168.1.20 port 2222 ssh2
Oct 10 10:03:12 server sshd[105]: Failed password for admin from 10.0.0.5 port 2222 ssh2
Oct 10 10:03:15 server sshd[106]: Failed password for root from 10.0.0.5 port 2223 ssh2
Oct 10 10:04:01 server sshd[107]: Accepted publickey for user from 192.168.1.30 port 2222 ssh2
"""


# Envio de arquivo de log
uploaded_file = st.file_uploader(
    "Envie um arquivo de log SSH",
    type=["log", "txt"],
)

if uploaded_file is not None:
    content = uploaded_file.getvalue().decode(
        "utf-8", errors="replace"
    )
    source_name = uploaded_file.name
else:
    content = SAMPLE_LOGS
    source_name = "Exemplo fictício"

st.info(f"Fonte analisada: {source_name}")


# Identifica eventos conhecidos
records = []

for line_number, line in enumerate(content.splitlines(), start=1):
    failed = "Failed password" in line

    accepted = (
        "Accepted password" in line
        or "Accepted publickey" in line
    )

    if not failed and not accepted:
        continue

    # Procura um endereço IPv4 na linha
    match = re.search(
        r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b",
        line,
    )

    if not match:
        continue

    ip = match.group(1)

    # Valida os valores do IPv4
    octets = [int(part) for part in ip.split(".")]

    if any(part > 255 for part in octets):
        continue

    event_type = (
        "Falha de autenticação"
        if failed
        else "Login aceito"
    )

    records.append({
        "Linha": line_number,
        "IP": ip,
        "Evento": event_type,
        "Log original": line,
    })


# Cria a tabela de eventos
df = pd.DataFrame(
    records,
    columns=["Linha", "IP", "Evento", "Log original"],
)


# Indicadores e gráficos
total_eventos = len(df)

if total_eventos == 0:
    st.warning(
        "Nenhum evento de autenticação reconhecido. "
        "Verifique se o arquivo contém logs SSH compatíveis."
    )

else:
    failures = df[
        df["Evento"] == "Falha de autenticação"
    ]

    successes = df[
        df["Evento"] == "Login aceito"
    ]

    # Conta falhas por endereço IP
    failures_by_ip = Counter(failures["IP"])

    # Sinaliza IPs com 3 ou mais falhas
    suspicious_ips = {
        ip: count
        for ip, count in failures_by_ip.items()
        if count >= 3
    }

    # Indicadores
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Eventos identificados", total_eventos)
    col2.metric("Falhas de autenticação", len(failures))
    col3.metric("Logins aceitos", len(successes))
    col4.metric("IPs sinalizados", len(suspicious_ips))

    # Gráfico de eventos por tipo
    st.subheader("📊 Eventos por tipo")

    events_counts = (
        df["Evento"]
        .value_counts()
        .rename_axis("Evento")
        .reset_index(name="Quantidade")
    )

    fig = px.bar(
        events_counts,
        x="Evento",
        y="Quantidade",
        color="Evento",
        title="Distribuição de eventos",
    )

    st.plotly_chart(fig, width="stretch")

    # Gráfico de falhas por IP
    st.subheader("🌐 Falhas por endereço IP")

    if failures.empty:
        st.success("Nenhuma falha de autenticação encontrada.")

    else:
        ip_counts = (
            failures["IP"]
            .value_counts()
            .rename_axis("IP")
            .reset_index(name="Falhas")
        )

        fig_ips = px.bar(
            ip_counts,
            x="IP",
            y="Falhas",
            title="Quantidade de falhas por IP",
        )
        fig_ips.update_yaxes(dtick=1)
        st.plotly_chart(fig_ips, width="stretch")

    # Alertas
    st.subheader("🚨 Alertas")

    if suspicious_ips:
        for ip, count in sorted(
            suspicious_ips.items(),
            key=lambda item: item[1],
            reverse=True,
        ):
            st.warning(
                f"{ip}: {count} falhas de autenticação. "
                "Investigue este padrão."
            )
    else:
        st.success(
            "Nenhum IP atingiu o limite configurado de 3 falhas."
        )

    # Tabela de eventos identificados
    st.subheader("📋 Eventos identificados")

    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
    )

    # Exportação para CSV
    csv_data = df.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="⬇️ Exportar eventos para CSV",
        data=csv_data,
        file_name="logsentinel_report.csv",
        mime="text/csv",
    )


st.divider()

st.caption(
    "LogSentinel — Projeto educacional. "
    "Alertas são indicadores para investigação, não provas de ataque."
)
