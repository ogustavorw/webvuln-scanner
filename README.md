![Testes](https://github.com/ogustavorw/webvuln-scanner/actions/workflows/tests.yml/badge.svg) 
 
 WebVuln Scanner

Scanner de vulnerabilidades web de linha de comando, desenvolvido em Python como projeto de portfólio para demonstrar habilidades em segurança ofensiva, engenharia de software e desenvolvimento de CLIs.

> ⚠️ **Aviso legal**: esta ferramenta foi criada exclusivamente para fins educacionais. Use-a **apenas em alvos que você possui ou tem autorização explícita para testar** (por exemplo, seus próprios sites ou ambientes de teste como o [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)). Escanear sistemas de terceiros sem autorização é ilegal.

 O que ele faz

O scanner analisa um alvo HTTP e reporta vulnerabilidades encontradas, classificadas por severidade (ALTA, MÉDIA, BAIXA). Atualmente ele verifica:

- **Headers de segurança ausentes** (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)

 Stack

- **Python 3.11+**
- **Typer** — CLI com subcomandos e help automático
- **httpx** — cliente HTTP
- **pytest** — testes automatizados

 Estrutura do projeto

```
webvuln-scanner/
├── pyproject.toml
├── src/
│   └── webvuln/
│       ├── cli.py               Interface de linha de comando (Typer)
│       ├── scanner.py           Orquestração: pré-check de conexão + execução dos módulos
│       ├── http_client.py       Cliente HTTP com tratamento de falhas
│       ├── models.py            Modelos de dados (ScanResult, Finding, Severity)
│       └── modules/
│           └── security_headers.py   Módulo de análise de headers
└── tests/
    └── ...                      Testes dos módulos com respostas simuladas
```

 Instalação

```bash
 Clone o repositório e entre na pasta
git clone https://github.com/seu-usuario/webvuln-scanner.git
cd webvuln-scanner

 Crie e ative o ambiente virtual
python -m venv .venv
source .venv/bin/activate

 Instale em modo editável, com dependências de desenvolvimento
pip install -e ".[dev]"
```

 Uso

```bash
webvuln scan https://seu-site.com
```

Exemplo de saída:

```
Alvo: https://seu-site.com

[ALTA] Header ausente: Content-Security-Policy
[ALTA] Header ausente: Strict-Transport-Security
[MÉDIA] Header ausente: X-Frame-Options
[BAIXA] Header ausente: Permissions-Policy

4 achado(s).
```

Se o alvo estiver inacessível (URL errada, site fora do ar), o scanner avisa explicitamente em vez de retornar "0 achados" — falha silenciosa é pior que erro explícito.

 Testes

```bash
pytest -v
```

Os testes usam respostas HTTP simuladas, então não dependem de internet nem de alvos externos.

 Estudo de caso: encontrando e corrigindo vulnerabilidades reais

Para validar a ferramenta, apliquei-a no meu próprio site em produção (`rawmodels.co`). O scanner encontrou **4 vulnerabilidades** — todas relacionadas a headers de segurança ausentes.

**Antes:**

```
[ALTA] Header ausente: Content-Security-Policy
[ALTA] Header ausente: Strict-Transport-Security
[MÉDIA] Header ausente: X-Frame-Options
[BAIXA] Header ausente: Permissions-Policy

4 achado(s).
```

**Correção** (site hospedado atrás da Cloudflare):

- **HSTS**: ativado em SSL/TLS → Edge Certificates (max-age de 6 meses, sem `includeSubDomains`/`preload` na primeira configuração)
- **X-Content-Type-Options**: ativado junto com o HSTS ("Plataforma sem sniff")
- **X-Frame-Options, Referrer-Policy, Permissions-Policy**: adicionados via Response Header Transform Rule aplicada a todo o domínio
- **CSP**: política construída iterativamente — comecei restritiva e fui adicionando as origens reais que o site usa (Google Fonts, CDN jsdelivr, Cloudflare Insights, API de países do formulário), validando cada ajuste pelo console do navegador

**Depois:**

```
Alvo: https://rawmodels.co/

0 achado(s).
```

 Lições do processo

- **Falha silenciosa é perigosa**: a primeira versão do scanner retornava "0 achados" quando não conseguia conectar ao alvo — parecia seguro quando na verdade nada havia sido verificado. Corrigi com um pré-check de conexão e mensagem de erro explícita.
- **Debug de camadas**: em um momento do processo, o navegador recebia a política CSP antiga enquanto o servidor já entregava a nova. O `curl -sI` confirmou que o header no ar estava correto, isolando o problema como cache do cliente — exatamente o fluxo de isolar camada de rede vs. camada de cliente.
- **CSP exige iteração**: uma política CSP não se escreve de uma vez. Ela se constrói contra os erros reais do console do navegador, origem por origem.

 Roadmap

- [ ] Módulo de enumeração de caminhos sensíveis (`/.env`, `/.git`, `/backup`)
- [ ] Suporte a alvos locais (OWASP Juice Shop via Docker) para testes reprodutíveis
- [ ] Saída em JSON/CSV para integração com pipelines
- [ ] Remoção do `unsafe-inline` do CSP do site de estudo de caso (migração do JS para arquivos externos)

 Autor

**Gustavo** — estudante de Engenharia de Software. Este projeto faz parte do meu portfólio de transição para segurança ofensiva/engenharia de software.

- LinkedIn: [www.linkedin.com/in/gustavo-ramos-woicekoscki-996067274]
- GitHub: [github.com/ogustavorw]