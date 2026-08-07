# Intelligent DNS Defense

Arquitetura em camadas para hardening e resposta assistida a ataques em
servidores DNS, executada em ambiente controlado.

## Camadas
1. Infraestrutura DNS (BIND9)
2. Hardening
3. Simulação de ataques (DNS Tunneling, Amplification, Fast Flux)
4. Monitoramento / Telemetria (BIND, Zeek, Suricata)
5. Intelligent DNS Defense (Code AI: observação, análise, resposta assistida)

## Estrutura
Ver a árvore de diretórios do repositório.

## Status
- Fase 1 (Telemetria): concluída — BIND, Zeek e Suricata capturando na rede do lab.
- Próximo: normalizador de eventos (as três fontes -> um schema JSON único).


## Licença
MIT — ver arquivo LICENSE.
