const fs = require("fs");
const csv = require("csv-parser");
const moment = require("moment");

function accessManagement(ip, threat_score) {
  if (!accessList.blocklist) {
      accessList.blocklist = [];
  }

  const index = accessList.blocklist.findIndex(item => item.ip === ip);

  // checka se o IP já não foi bloqueado
  if (index !== -1) {
      const listTimestamp = accessList.blocklist[index].timestamp;
      const currentTimestamp = moment();
      const timeDiff = moment.duration(currentTimestamp.diff(moment(listTimestamp))).asHours();

      if (timeDiff > 12) {
          // remove o registro caso possua mais de 12h de bloqueio
          accessList.blocklist.splice(index, 1);
          fs.writeFileSync("access-list.json", JSON.stringify(accessList, null, 2));
          return;
      } else {
          // retorna para não regravação de itens registrados
          return;
      }
  }

  let threat_level = "Medium";

  if(threat_score > 2)
    threat_level = "High";

  const newTimestamp = moment().toISOString(); // Gera um timestamp ISO 8601
  accessList.blocklist.push({ ip, threat_level, timestamp: newTimestamp });

  // escreve o novo JSON no arquivo
  fs.writeFileSync("access-list.json", JSON.stringify(accessList, null, 2));
}

// recebe um array de objetos e checka se a alguma extensão ou conteúdo malicioso está no path da requisição
function pathAnalysis(group, extensions, chars, caseSensitive = false) {
  const regexExt = new RegExp(`(\.${extensions.join('|')})$`, caseSensitive ? '' : 'i');
  const regexChars = new RegExp(`[${chars.join('\\')}]`, 'g');
  let clientIp = null;

  group.forEach(log => {
    const path = log.ClientRequestPath;
    // caso tenha, já retorna o IP malicioso sem a necessidade de inspecionar todo o grupo
    if (regexExt.test(path) || regexChars.test(path)) {
      clientIp = log.ClientIP;
      return clientIp;
    }
  });

  return clientIp;
}

function agentAnalysis(group, agents, caseSensitive = false) {
  let clientIp = null;

  group.forEach(log => {
    let path = log.ClientRequestUserAgent;

    // evitar o bypass através de mudança no case
    path = caseSensitive ? path : path.toLowerCase();

    // checka se tem algum UA malicioso dentro do array de objetos
    for (const agent of agents) {
      let userAgent = caseSensitive ? agent : agent.toLowerCase();
      if (path.includes(userAgent)) {
        clientIp = log.ClientIP;
        break;
      }
    }
  });

  return clientIp;
}

function ipAnalysis(ip_group) {
  // array para armazenar os motivos de suspeita do cliente
  let susActions = [];
  threat_score = 0;

  if (!accessList.whitelist)
    accessList.whitelist = [];

  // caso o IP esteja na whitelist ele não é inspecionado
  if(accessList.whitelist.includes(ip_group[0].ClientIP)){
    const logMessage = `[i] ${currentIp} possui acesso ao ambiente\n`;
    fs.appendFileSync(entryPath, logMessage);
    return;
  }
    

  // analisando as extensões do arquivo
  currentIp = pathAnalysis(ip_group, configJson.firewall_rules.block_ext, configJson.firewall_rules.suspicious_chars);
  if(currentIp){
    threat_score += 2;
    susActions.push("Conteúdo Suspeito");
  }
    
  // analisando o user-agent 
  if(agentAnalysis(ip_group, configJson.firewall_rules.block_user_agent)){
    threat_score += 1;
    susActions.push("User Agent malicioso");
  }

  // analisando a possibilidade de um DDos de acordo com o padrão estabelecido nas configurações do firewall
  if(Number(ip_group.length) > Number(configJson.firewall_rules.req_rules["max_requests"])){
    threat_score += 1;
    susActions.push("Possível ataque DDoS ou DoS");
  }
    

  // classifica de acordo com o score da ameaça
  if(threat_score > 2){
    accessManagement(currentIp, threat_score);
  }else if(threat_score >= 1){
    let logMessage = `[!] ${currentIp} está executando ações suspeitas: ${susActions}\n`;
    fs.appendFileSync(logsPath, logMessage);
    logMessage = `[i] ${currentIp} possui acesso ao ambiente.\n`;
    fs.appendFileSync(entryPath, logMessage);
  }
}

// processa o csv bloco a bloco de IPs e chama a função ipAnalysis que trata os logs por grupo de IPs únicos
function logAnalysis(filePath) {
  const results = [];

  // cria um stream com o csv e busca por todo arquivo ocorrencias com o mesmo IP para agrupa-las
  fs.createReadStream(filePath)
    .pipe(csv())
    .on('data', (data) => {
      const group = results.find(g => g[0].ClientIP === data.ClientIP);
      if (group) {
        group.push(data);
      } else {
        results.push([data]);
      }
    })
    .on('end', () => {
      results.forEach(group => {
        ipAnalysis(group);
      });
      console.log("[i] todo o arquivo csv foi processado e análisado com sucesso!")
    });
}

logAnalysis("test-dataset.csv");
let rawdata = fs.readFileSync("rules.json");
const configJson = JSON.parse(rawdata);
rawdata = fs.readFileSync("access-list.json");
const accessList = JSON.parse(rawdata);

const entryPath = "logs/entry_logs.txt"
const logsPath = "logs/logs.txt"