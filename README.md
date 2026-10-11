# PRI-project-g74

Projeto de recuperação de informação sobre vulnerabilidades CVE. A pipeline
recolhe dados do NVD e do GitHub Advisory Database (GHAD), prepara os dados e
gera uma coleção final para análise e indexação.

## Requisitos

- Python 3
- `make`
- `git`

## Executar a pipeline

Na root do repositório, correr:

```bash
make run
```

O comando cria o ambiente virtual `venv` se necessário, instala as dependências
de `requirements.txt` e executa, por ordem:

1. `nvd_collection.py`: clona e filtra os dados NVD;
2. `nvd_preparation.py`: cria `selected_cves.csv`;
3. `ghad_collection.py`: clona o GitHub Advisory Database;
4. `ghad_preparation.py`: cruza e enriquece o csv no `final_cves.csv`.


## Executar a caracterização

Depois de a pipeline gerar `final_cves.csv`, executar:

```bash
venv/bin/python characterizer.py
```

## Outros comandos

Para apenas preparar o ambiente e instalar dependências:

```bash
make setup
make install
```

Para remover o ambiente virtual e ficheiros Python compilados:

```bash
make clean
```
