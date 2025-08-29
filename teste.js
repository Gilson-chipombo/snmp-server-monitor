const express = require("express");
const snmp = require("net-snmp");

const app = express();
app.use(express.json());

const monitorData = [];

const monitoredDevices = [
    {
        ip: "192.168.220.134",
        community: "public",
        oids: [
            "1.3.6.1.2.1.1.1.0", // sysDescr
            "1.3.6.1.2.1.1.3.0", // sysUpTime
            "1.3.6.1.4.1.9.2.1.56.0", // CPU 5 sec
            "1.3.6.1.4.1.9.2.1.58.0", // CPU 5 min
            "1.3.6.1.4.1.9.2.1.8.0",  // Memória livre
            "1.3.6.1.4.1.9.2.1.9.0",  // Memória usada
            "1.3.6.1.2.1.2.2.1.8.2"   // ifOperStatus (Interface 2)
        ]
    },
    {
        ip: "192.168.10.1",
        community: "public",
        oids: [
            "1.3.6.1.2.1.1.1.0", // sysDescr
            "1.3.6.1.2.1.1.3.0", // sysUpTime
            "1.3.6.1.4.1.9.2.1.58.0", // CPU 5 min
            "1.3.6.1.4.1.9.2.1.8.0",  // Memória livre
            "1.3.6.1.4.1.9.2.1.9.0",  // Memória usada
            "1.3.6.1.2.1.2.2.1.8.2"   // ifOperStatus (Interface 2)
        ]
    },
    {
        ip: "192.168.20.1",
        community: "public",
        oids: [
            "1.3.6.1.2.1.1.1.0", // sysDescr
            "1.3.6.1.2.1.1.3.0", // sysUpTime
            "1.3.6.1.4.1.9.2.1.58.0", // CPU 5 min
            "1.3.6.1.4.1.9.2.1.8.0",  // Memória livre
            "1.3.6.1.4.1.9.2.1.9.0",  // Memória usada
            "1.3.6.1.2.1.2.2.1.8.2"   // ifOperStatus (Interface 2)
        ]
    }
];

const OIDS = {
    ifIndex: "1.3.6.1.2.1.2.2.1.1",      // Índices das interfaces
    ifDescr: "1.3.6.1.2.1.2.2.1.2",      // Nome da interface
    ifOperStatus: "1.3.6.1.2.1.2.2.1.8", // Estado da interface
    ifSpeed: "1.3.6.1.2.1.2.2.1.5",      // Velocidade da interface
    ipAdEntIfIndex: "1.3.6.1.2.1.4.20.1.2", // Mapeamento IP -> ifIndex
    ipAdEntAddr: "1.3.6.1.2.1.4.20.1.1",    // Endereços IP
    sysName: "1.3.6.1.2.1.1.5.0"            // Nome do dispositivo
};

// Cria uma sessão SNMP com timeout
function createSession(ip, community) {
    return snmp.createSession(ip, community, {
        timeout: 30000,
        version: snmp.Version2c
    });
}

// Converte valores SNMP de forma segura
function safeSnmpValue(value, type) {
    if (Buffer.isBuffer(value)) {
        return value.toString("utf8");
    } else if (typeof value === "number" || type === 2 || type === 64) {
        return value.toString();
    } else if (value === null || value === undefined) {
        return "N/A";
    }
    return value.toString();
}

// Executa SNMP Get para OIDs específicos
function getSnmpData(ip, community, oids) {
    return new Promise((resolve, reject) => {
        const session = createSession(ip, community);
        session.get(oids, (error, varbinds) => {
            session.close();
            if (error) {
                console.error(`[ERROR] getSnmpData para ${oids}:`, error);
                reject(error);
            } else {
                const result = {};
                varbinds.forEach((vb) => {
                    if (!snmp.isVarbindError(vb)) {
                        result[vb.oid] = safeSnmpValue(vb.value, vb.type);
                    } else {
                        console.warn(`[WARN] Erro em varbind para ${vb.oid}:`, vb);
                        result[vb.oid] = "N/A";
                    }
                });
                console.log(`[DEBUG] getSnmpData para ${oids}:`, result);
                resolve(result);
            }
        });
    });
}

// Executa SNMP Walk para uma árvore OID
function snmpWalk(ip, community, oid) {
    return new Promise((resolve, reject) => {
        const session = createSession(ip, community);
        const results = [];

        session.subtree(oid, (varbind) => {
            console.log(`[DEBUG] Varbind recebido para ${oid}:`, JSON.stringify(varbind, null, 2));
            results.push({
                oid: varbind.oid || "unknown",
                value: safeSnmpValue(varbind.value, varbind.type),
                type: varbind.type
            });
        }, (error) => {
            session.close();
            if (error) {
                console.error(`[ERROR] snmpWalk para ${oid} falhou:`, error);
                reject(error);
            } else {
                console.log(`[DEBUG] snmpWalk para ${oid}:`, results);
                resolve(results);
            }
        });
    });
}

// Extrai IP ou ifIndex do OID
function extractValueFromOid(oid, baseOid) {
    if (!oid || typeof oid !== "string") {
        console.warn(`[WARN] OID inválido: ${oid}`);
        return null;
    }
    const normalizedOid = oid.replace(/^iso\.3\.6\.1/, "1.3.6.1").replace(/^so\.3\.6\.1/, "1.3.6.1");
    if (normalizedOid.startsWith(baseOid)) {
        const suffix = normalizedOid.slice(baseOid.length + 1);
        const parts = suffix.split(".");
        if (parts.length === 4) {
            return parts.join("."); // Para IPs
        } else if (parts.length === 1) {
            return parts[0]; 
        }
    }
    console.warn(`[WARN] OID ${oid} não corresponde a ${baseOid}`);
    return null;
}

// Obtém a lista de IPs dinamicamente
async function getIpList(ip, community) {
    try {
        const ipAddrData = await snmpWalk(ip, community, OIDS.ipAdEntAddr);
        const ipList = ipAddrData
            .map(({ oid }) => extractValueFromOid(oid, OIDS.ipAdEntAddr))
            .filter(ip => ip);
        console.log(`[DEBUG] Lista de IPs obtida:`, ipList);
        return ipList;
    } catch (err) {
        console.warn(`[WARN] Falha ao consultar ipAdEntAddr:`, err);
        return [];
    }
}

// Obtém a lista de ifIndex dinamicamente
async function getIfIndexes(ip, community) {
    try {
        const ifIndexData = await snmpWalk(ip, community, OIDS.ifIndex);
        const ifIndexes = ifIndexData
            .map(({ oid }) => extractValueFromOid(oid, OIDS.ifIndex))
            .filter(index => index);
        console.log(`[DEBUG] Lista de ifIndex obtida:`, ifIndexes);
        return ifIndexes;
    } catch (err) {
        console.warn(`[WARN] Falha ao consultar ifIndex:`, err);
        return [];
    }
}

// Obtém o mapeamento de IPs para ifIndex
async function getIpMap(ip, community, ipList) {
    const ipMap = {};
    try {
        const ipAdEntIfIndexData = await snmpWalk(ip, community, OIDS.ipAdEntIfIndex);
        console.log(`[DEBUG] ipAdEntIfIndexData:`, ipAdEntIfIndexData);
        for (const { oid, value } of ipAdEntIfIndexData) {
            const ip = extractValueFromOid(oid, OIDS.ipAdEntIfIndex);
            if (ip && value !== "N/A") {
                ipMap[value] = ip;
            }
        }
        if (Object.keys(ipMap).length > 0) {
            console.log(`[DEBUG] ipMap obtido com snmpWalk:`, ipMap);
            return ipMap;
        }
    } catch (err) {
        console.warn(`[WARN] Falha ao consultar ipAdEntIfIndex com snmpWalk:`, err);
    }

    // Fallback com getSnmpData apenas se snmpWalk falhar
    if (ipList.length > 0) {
        console.log(`[INFO] Usando fallback com getSnmpData para IPs:`, ipList);
        const ipOids = ipList.map(ip => `${OIDS.ipAdEntIfIndex}.${ip}`);
        try {
            const ipData = await getSnmpData(ip, community, ipOids);
            for (const ip of ipList) {
                const oid = `${OIDS.ipAdEntIfIndex}.${ip}`;
                if (ipData[oid] && ipData[oid] !== "N/A") {
                    ipMap[ipData[oid]] = ip;
                }
            }
        } catch (getErr) {
            console.warn(`[WARN] Falha ao consultar ipAdEntIfIndex com getSnmpData:`, getErr);
        }
    }
    console.log(`[DEBUG] ipMap final:`, ipMap);
    return ipMap;
}

// Função de monitoramento de dispositivos
async function monitorDevices() {
    console.log("Coletando dados SNMP...");
    for (const device of monitoredDevices) {
        try {
            // Obter sysName para identificar o dispositivo
            let sysName = "Desconhecido";
            try {
                const sysNameData = await getSnmpData(device.ip, device.community, [OIDS.sysName]);
                sysName = sysNameData[OIDS.sysName] || "Desconhecido";
            } catch (err) {
                console.warn(`[WARN] Falha ao obter sysName para ${device.ip}:`, err.message);
            }

            // Obter dados SNMP
            const data = await getSnmpData(device.ip, device.community, device.oids);
            const formattedData = {
                timestamp: new Date().toISOString(),
                ip: device.ip,
                sysName,
                metrics: {
                    sysDescr: data["1.3.6.1.2.1.1.1.0"],
                    sysUpTime: data["1.3.6.1.2.1.1.3.0"],
                    cpu5Sec: data["1.3.6.1.4.1.9.2.1.56.0"],
                    cpu5Min: data["1.3.6.1.4.1.9.2.1.58.0"],
                    memFree: data["1.3.6.1.4.1.9.2.1.8.0"],
                    memUsed: data["1.3.6.1.4.1.9.2.1.9.0"],
                    ifOperStatus: data["1.3.6.1.2.1.2.2.1.8.2"]
                }
            };


            console.log(`[INFO] Métricas coletadas para ${sysName} (${device.ip}):`);
            console.log(JSON.stringify(formattedData, null, 2));

            // Armazenar dados
            monitorData.push(formattedData);

            // Verificar se a interface está DOWN
            if (data["1.3.6.1.2.1.2.2.1.8.2"] !== "1") {
                // Obter nome da interface
                let ifDescr = "Interface 2";
                try {
                    const ifDescrData = await getSnmpData(device.ip, device.community, ["1.3.6.1.2.1.2.2.1.2.2"]);
                    ifDescr = ifDescrData["1.3.6.1.2.1.2.2.1.2.2"] || "Interface 2";
                } catch (err) {
                    console.warn(`[WARN] Falha ao obter ifDescr para ${device.ip}:`, err.message);
                }
                console.error(`[ERROR] Dispositivo ${sysName} (${device.ip}): Interface ${ifDescr} caiu`);
            }
        } catch (err) {
            let sysName = "Desconhecido";
            try {
                const sysNameData = await getSnmpData(device.ip, device.community, [OIDS.sysName]);
                sysName = sysNameData[OIDS.sysName] || "Desconhecido";
            } catch (sysErr) {
                console.warn(`[WARN] Falha ao obter sysName para ${device.ip}:`, sysErr.message);
            }

            // Verificar se o erro está relacionado ao ifOperStatus
            if (err.message.includes("1.3.6.1.2.1.2.2.1.8.2")) {
                let ifDescr = "Interface 2";
                try {
                    const ifDescrData = await getSnmpData(device.ip, device.community, ["1.3.6.1.2.1.2.2.1.2.2"]);
                    ifDescr = ifDescrData["1.3.6.1.2.1.2.2.1.2.2"] || "Interface 2";
                } catch (ifErr) {
                    console.warn(`[WARN] Falha ao obter ifDescr para ${device.ip}:`, ifErr.message);
                }
                console.error(`[ERROR] Dispositivo ${sysName} (${device.ip}): Interface ${ifDescr} caiu`, err.message);
            } else {
                console.error(`[ERROR] Erro ao coletar dados do dispositivo ${sysName} (${device.ip}):`, err.message);
            }
        }
    }
}

// Iniciar monitoramento
setInterval(monitorDevices, 1000);

app.get("/interfaces/:ip", async (req, res) => {
    const { ip } = req.params;
    try {
        // Obtém ifIndex dinamicamente
        const ifIndexes = await getIfIndexes(ip, "public");
        if (ifIndexes.length === 0) {
            return res.status(200).json({ message: "Nenhuma interface encontrada", data: [] });
        }

        // Obtém IPs e mapeamento
        const ipList = await getIpList(ip, "public");
        const ipMap = await getIpMap(ip, "public", ipList);

        const interfaces = [];
        for (const ifIndex of ifIndexes) {
            const oids = [
                `${OIDS.ifDescr}.${ifIndex}`,
                `${OIDS.ifOperStatus}.${ifIndex}`,
                `${OIDS.ifSpeed}.${ifIndex}`
            ];
            try {
                const data = await getSnmpData(ip, "public", oids);
                interfaces.push({
                    ifIndex,
                    name: data[oids[0]] || "N/A",
                    ip: ipMap[ifIndex] || null,
                    status: data[oids[1]] === "1" ? "UP" : "DOWN",
                    speed: data[oids[2]] && parseInt(data[oids[2]]) < 4294967295
                        ? `${parseInt(data[oids[2]]) / 1000000} Mbps`
                        : "N/A"
                });
            } catch (err) {
                console.warn(`[WARN] Falha ao consultar ifIndex ${ifIndex} para ${ip}:`, err);
            }
        }

        res.json(interfaces);
    } catch (err) {
        console.error(`[ERROR] Erro na rota /interfaces/${ip}:`, err);
        res.status(500).json({ error: err.message });
    }
});

app.get("/interface/:ip/:id", async (req, res) => {
    const { ip, id } = req.params;
    const oids = [
        `${OIDS.ifDescr}.${id}`,
        `${OIDS.ifOperStatus}.${id}`,
        `${OIDS.ifSpeed}.${id}`
    ];

    try {
        const data = await getSnmpData(ip, "public", oids);

        // Obtém IPs e mapeamento
        const ipList = await getIpList(ip, "public");
        let ipAddr = null;
        try {
            const ipAdEntIfIndexData = await snmpWalk(ip, "public", OIDS.ipAdEntIfIndex);
            console.log(`[DEBUG] ipAdEntIfIndexData para ifIndex ${id}:`, ipAdEntIfIndexData);
            for (const { oid, value } of ipAdEntIfIndexData) {
                if (value === id) {
                    ipAddr = extractValueFromOid(oid, OIDS.ipAdEntIfIndex);
                    break;
                }
            }
            if (ipAddr) {
                console.log(`[DEBUG] IP encontrado para ifIndex ${id} com snmpWalk: ${ipAddr}`);
            }
        } catch (err) {
            console.warn(`[WARN] Falha ao consultar ipAdEntIfIndex com snmpWalk para ifIndex ${id}:`, err);
            if (ipList.length > 0) {
                console.log(`[INFO] Usando fallback com getSnmpData para ifIndex ${id}`);
                const ipOids = ipList.map(ip => `${OIDS.ipAdEntIfIndex}.${ip}`);
                try {
                    const ipData = await getSnmpData(ip, "public", ipOids);
                    console.log(`[DEBUG] ipData para ifIndex ${id}:`, ipData);
                    for (const knownIp of ipList) {
                        const oid = `${OIDS.ipAdEntIfIndex}.${knownIp}`;
                        if (ipData[oid] === id) {
                            ipAddr = knownIp;
                            break;
                        }
                    }
                } catch (getErr) {
                    console.warn(`[WARN] Falha ao consultar ipAdEntIfIndex com getSnmpData para ifIndex ${id}:`, getErr);
                }
            }
        }

        res.json({
            ifIndex: id,
            name: data[oids[0]] || "N/A",
            status: data[oids[1]] === "1" ? "UP" : "DOWN",
            speed: data[oids[2]] && parseInt(data[oids[2]]) < 4294967295
                ? `${parseInt(data[oids[2]]) / 1000000} Mbps`
                : "N/A",
            ip: ipAddr || null
        });
    } catch (err) {
        console.error(`[ERROR] Erro na rota /interface/${ip}/${id}:`, err);
        if (err.status === snmp.ErrorStatus.NoSuchName) {
            return res.status(404).json({ error: `Interface com ifIndex ${id} não encontrada` });
        }
        res.status(500).json({ error: err.message });
    }
});

// Rota para exibir dados coletados
app.get("/monitor", (req, res) => {
    res.json(monitorData);
});

app.listen(5000, () => {
    console.log("🚀 API rodando em http://localhost:5000");
});