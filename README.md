# Auth Event Lens · C# / .NET

[![Tests](https://github.com/alefkaue/auth-event-lens/actions/workflows/tests.yml/badge.svg)](https://github.com/alefkaue/auth-event-lens/actions/workflows/tests.yml)

Ferramenta de triagem **offline em C#** para eventos de autenticação normalizados. Identifica padrões de falha em múltiplas contas a partir do mesmo IP e login bem-sucedido após falha da mesma conta. Gera evidências por número de linha, sem acessar máquinas ou consultar serviços externos.

## Executar

Requer SDK .NET 10. Não usa pacotes NuGet externos; usa as bibliotecas do .NET.

```console
git clone https://github.com/alefkaue/auth-event-lens.git
cd auth-event-lens
dotnet build src/AuthEventLens/AuthEventLens.csproj -c Release
dotnet run --project tests/AuthEventLens.Tests -c Release
dotnet run --project src/AuthEventLens -c Release --no-build -- examples/events.jsonl
```

O exemplo produz dois achados:

| Regra | Evidências |
| --- | --- |
| `password_spray_pattern` | Falhas de alice, bob e carol nas linhas 1, 2 e 3 |
| `success_after_failure` | Falha e sucesso de alice nas linhas 1 e 4 |

```console
dotnet run --project src/AuthEventLens -c Release --no-build -- examples/clean.jsonl
dotnet run --project src/AuthEventLens -c Release --no-build -- examples/events.jsonl 4 300
```

O primeiro comando não gera achados. No segundo, o limiar sobe para quatro contas distintas: o achado de spray desaparece, mas o sucesso após falha continua sendo sinalizado. Padrões: três contas em janela inclusiva de 300 segundos. Janela configurável entre 1 e 86400 segundos.

Saída JSON. Código de saída: **0** sem achados, **1** com achados, **2** erro. Falha seguida de sucesso pode ser apenas erro de digitação: é um sinal de triagem, não confirmação de ataque.

## Entrada normalizada

Um objeto JSON por linha, com exatamente cinco campos:

```json
{"timestamp":"2026-01-01T12:00:00Z","eventId":4625,"user":"LAB\\alice","sourceIp":"192.0.2.40","logonType":3}
```

Não lê `.evtx`, XML do Event Viewer nem exportações arbitrárias diretamente. É necessário normalizar antes: `timestamp` recebe o instante com fuso, `eventId` recebe EventID, `user` identifica a conta alvo incluindo domínio/computador, `sourceIp` recebe o endereço de origem e `logonType` recebe o tipo de logon.

Analisa eventos **4625** (falha) e **4624** (sucesso), com tipos de logon **3** (Network) e **10** (RemoteInteractive). Outros IDs/tipos com schema válido são contados em `ignoredEvents`. IP ausente ou `-` e qualquer linha malformada causam erro, sem produzir relatório parcial. Linhas vazias são ignoradas.

## Decisões e limites

`JSONL → validação → ordenação temporal → janela por IP → correlação → JSON`. IPv4-mapped IPv6 é normalizado para IPv4. Contas são comparadas sem diferenciar caixa, preservando domínio/computador. Não combine contas locais de máquinas distintas sob o mesmo identificador.

Spray gera um achado ao atingir o limiar de contas distintas; evita repetição enquanto o limiar se mantém. Um sucesso correlacionado remove da janela as falhas daquela conta, preservando as demais. Cada achado contém IP, instante, contas e `evidenceLines`.

O limite é de 100 mil linhas e 65536 caracteres por linha. Os eventos são ordenados em memória e as janelas usam listas; não é um SIEM nem um processador de alto volume. Eventos duplicados não são deduplicados. Não interpreta status/substatus, origem do provedor ou sessões; a normalização deve preservar a procedência dos eventos.

NAT pode agrupar usuários legítimos. Ataques distribuídos ou lentos podem não atingir o limiar. Login após falha não comprova comprometimento. O relatório contém usuários e IPs; trate-o como informação de investigação.

## Testes e referências

O runner de testes é um executável sem dependências externas, executado por `dotnet run --project tests/AuthEventLens.Tests`, e não por `dotnet test`. Verifica correlação, evidências, contas distintas, separação por IP, caixa, janela inclusiva, ordenação, expiração e entradas inválidas. CI: Windows/Linux.

- [Microsoft: evento 4625 e tipos de logon](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Microsoft: evento 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)

Próxima evolução: importador XML com validação do provedor e identificação de máquina. Projeto educacional independente, desenvolvido com assistência de IA, com exemplos sintéticos. Licença MIT.
