# Desafio

Criação de um script que simule como um firewall avalia e filtra o tráfego.

# Método de análise

Por questões de performance o código busca por ocorrencias do mesmo IP no dataset e os agrupa em um array de objetos, array esse que é levado pra análise posteriormente.

Caso os dados de entrada fossem ordenados pelo timestamp, poderíamos realizar a análise através de "janelas deslizantes" o que seria interessante para determinadas implementações e também no gerenciamento de memória, porém, dado o escopo do case optei por não realizar nenhuma alteração nos dados originais (o csv)

# Funções

1 - Análise de quantidades de requisições por dia (para captura de possiveis ataques de sobrecarga como DoS ou DDoS)

2 - Análise de extensões solicitadas (para buscar possíveis sinks/sources maliciosas e tentativas de execuções de comando

3 - Inspeção de caracteres suspeitos como: "<", ">", "^", "\", "-"

4 - Busca por User-Agents maliciosos

# Como funcionam as regras?

Todas as regras são implementadas no arquivo rules.json, onde é possível incluir e excluir conteúdo sem alterar o código do firewall.

nesse arquivo você pode:

incluir/remover extensões
incluir/remover caracteres suspeitos
incluir/remover UAs
alterar o tempo máximo de bloqueio de um usuário
alterar a quantidade máxima de requisições suspeitas

# Logs

Todos os logs são feitos no arquivo logs.txt, esses logs são referentes a usuários suspeitos (que podem ser bloqueados na lista de bloqueios), obs: usuários bloqueados não possuem logs pois não podem acessar as aplicações do ambiente.

os logs contém tanto o IP quanto o motivo da monitoração (para futura investigação do administrador da rede).

O arquivo entry_logs.txt possui registro de TODOS os acessos não bloqueados no ambiente.

# Lista de acessos

A lista de acessos é um arquivo json que possui tanto a whitelist quanto a blocklist, a estrutura do arquivo é: 

\- Blocklist:

	Ip
 
	Threat_Level
 
	TimeStamp
 
 
\- Whitelist:

	Ip
 

o timestamp é utilizado para registro desbloqueio após 12h	

obs: a lista de permissões tem prioridade sobre a lista de bloqueios.

# Como utilizar?

Para testar o script comece baixando as dependencias do projeto:

```
npm install 
```

após isso, execute:

```
node index.js
```

Em seguida, você pode configurar ou alterar manualmente as regras do firewall inserindo ou removendo os itens desejados nos arquivos do projeto.

