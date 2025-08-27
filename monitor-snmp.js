const express = require("express");
const snmp = require("net-snmp");

const app = express();
app.use(express.json());

const device = { ip: "192.168.10.1", community: "public" };

// OIDs das tabelas SNMP
const OIDS = {
    ifDescr: "1.3.6.1.2.1.2.2.1.2",      // Nome da interface
    ifOperStatus: "1.3.6.1.2.1.2.2.1.8", // Estado da interface
    ifSpeed: "1.3.6.1.2.1.2.2.1.5",      // Velocidade da interface
    ipAdEntIfIndex: "1.3.6.1.2.1.4.20.1.2", // Mapeamento IP -> Interface
    ipAdEntAddr: "1.3.6.1.2.1.4.20.1.1",    // Endereços IP
    atIfIndex: "1.3.6.1.2.1.3.1.1.3"        // Tabela ARP
};

// IPs conhecidos como fallback
const FALLBACK_IPS = ["42.42.42.1", "42.42.42.2", "192.168.10.1", "192.168.20.1"];

// Função para criar sessão SNMP com opções de timeout
function createSession(ip, community) {
    return snmp.createSession(ip, community, {
        timeout: 30000, // 30 segundos de timeout
        version: snmp.Version2c
    });
}


function safeSnmpValue(value, type) {
    if (Buffer.isBuffer(value)) {
        return value.toString("utf8"); // Converte Buffer para string UTF-8
    } else if (typeof value === "number" || type === 2 || type === 64) {
        return value.toString(); // Converte número ou tipos INTEGER/IpAddress
    } else if (value === null || value === undefined) {
        return "N/A"; // Trata valores nulos ou indefinidos
    } else {
        return value.toString(); // Outros tipos
    }
}

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
                    }
                });
                console.log(`[DEBUG] getSnmpData para ${oids}:`, result);
                resolve(result);
            }
        });
    });
}

function snmpWalk(ip, community, oid) {
    return new Promise((resolve, reject) => {
        const session = createSession(ip, community);
        const results = [];

        session.subtree(oid, (varbind) => {
            // Log completo do varbind para depuração
            console.log(`[DEBUG] Varbind recebido para ${oid}:`, JSON.stringify(varbind, null, 2));
            // Aceitar qualquer varbind, independentemente de validação
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

// Função auxiliar para extrair IP do OID
function extractIpFromOid(oid, baseOid) {
    if (!oid || typeof oid !== "string") {
        console.warn(`[WARN] OID inválido para IP: ${oid}`);
        return null;
    }
    let normalizedOid = oid.replace(/^iso\.3\.6\.1/, "1.3.6.1").replace(/^so\.3\.6\.1/, "1.3.6.1");
    if (normalizedOid.startsWith(baseOid)) {
        const ipParts = normalizedOid.split(".").slice(-4);
        if (ipParts.length === 4) {
            return ipParts.join(".");
        }
    }
    console.warn(`[WARN] OID ${oid} não corresponde a ${baseOid} para IP`);
    return null;
}


app.get("/interfaces", async (req, res) => {
    try {
        // Assumindo ifIndex de 1 a 20 com base na saída fornecida
        const ifIndexes = Array.from({ length: 20 }, (_, i) => (i + 1).toString());
        const interfaces = [];
        const ipMap = {};

        // Consultar atIfIndex (tabela ARP) para mapear IPs aos ifIndex
        let atIfIndexData = [];
        try {
            atIfIndexData = await snmpWalk(device.ip, device.community, OIDS.atIfIndex);
            console.log(`[DEBUG] atIfIndexData:`, atIfIndexData);
            for (const { oid, value } of atIfIndexData) {
                const ip = extractIpFromOid(oid, OIDS.atIfIndex);
                if (ip && value !== "N/A") {
                    ipMap[value] = ip;
                }
            }
        } catch (err) {
            console.warn(`[WARN] Falha ao consultar atIfIndex:`, err);
        }

        // Fallback: consultar ipAdEntIfIndex com snmpWalk
        if (Object.keys(ipMap).length === 0) {
            console.log(`[INFO] Usando fallback para ipAdEntIfIndex com snmpWalk`);
            try {
                const ipAdEntIfIndexData = await snmpWalk(device.ip, device.community, OIDS.ipAdEntIfIndex);
                console.log(`[DEBUG] ipAdEntIfIndexData:`, ipAdEntIfIndexData);
                for (const { oid, value } of ipAdEntIfIndexData) {
                    const ip = extractIpFromOid(oid, OIDS.ipAdEntIfIndex);
                    if (ip && value !== "N/A") {
                        ipMap[value] = ip;
                    }
                }
            } catch (err) {
                console.warn(`[WARN] Falha ao consultar ipAdEntIfIndex com snmpWalk:`, err);
            }
        }

        // Fallback adicional: consultar ipAdEntIfIndex com getSnmpData
        if (Object.keys(ipMap).length === 0) {
            console.log(`[INFO] Usando fallback com getSnmpData para IPs conhecidos:`, FALLBACK_IPS);
            const ipOids = FALLBACK_IPS.map(ip => `${OIDS.ipAdEntIfIndex}.${ip}`);
            try {
                const ipData = await getSnmpData(device.ip, device.community, ipOids);
                for (const ip of FALLBACK_IPS) {
                    const oid = `${OIDS.ipAdEntIfIndex}.${ip}`;
                    if (ipData[oid] && ipData[oid] !== "N/A") {
                        ipMap[ipData[oid]] = ip;
                    }
                }
            } catch (err) {
                console.warn(`[WARN] Falha ao consultar ipAdEntIfIndex com getSnmpData:`, err);
            }
        }

        console.log(`[DEBUG] ipMap final:`, ipMap);

        // Consultar cada interface com getSnmpData
        for (const ifIndex of ifIndexes) {
            const oids = [
                `${OIDS.ifDescr}.${ifIndex}`,
                `${OIDS.ifOperStatus}.${ifIndex}`,
                `${OIDS.ifSpeed}.${ifIndex}`
            ];
            try {
                const data = await getSnmpData(device.ip, device.community, oids);
                interfaces.push({
                    ifIndex,
                    name: data[oids[0]] || "N/A",
                    ip: ipMap[ifIndex] || null,
                    status: data[oids[1]] === "1" ? "UP" : "DOWN",
                    speed: data[oids[2]] ? `${parseInt(data[oids[2]]) / 1000000} Mbps` : "N/A"
                });
            } catch (err) {
                console.warn(`[WARN] Falha ao consultar ifIndex ${ifIndex}:`, err);
            }
        }

        if (interfaces.length === 0) {
            return res.status(200).json({ message: "Nenhuma interface encontrada", data: [] });
        }

        res.json(interfaces);
    } catch (err) {
        console.error("[ERROR] Erro na rota /interfaces:", err);
        res.status(500).json({ error: err.message });
    }
});

app.get("/interface/:id", async (req, res) => {
    const { id } = req.params;
    const oids = [
        `${OIDS.ifDescr}.${id}`,      
        `${OIDS.ifOperStatus}.${id}`, 
        `${OIDS.ifSpeed}.${id}`
    ];

    try {
        const data = await getSnmpData(device.ip, device.community, oids);

        // Tentar consultar IPs com atIfIndex
        let ip = null;
        try {
            const atIfIndexData = await snmpWalk(device.ip, device.community, OIDS.atIfIndex);
            for (const { oid, value } of atIfIndexData) {
                if (value === id) {
                    ip = extractIpFromOid(oid, OIDS.atIfIndex);
                    break;
                }
            }
        } catch (err) {
            console.warn(`[WARN] Falha ao consultar atIfIndex para ifIndex ${id}:`, err);
            // Fallback com ipAdEntIfIndex (snmpWalk)
            try {
                const ipAdEntIfIndexData = await snmpWalk(device.ip, device.community, OIDS.ipAdEntIfIndex);
                for (const { oid, value } of ipAdEntIfIndexData) {
                    if (value === id) {
                        ip = extractIpFromOid(oid, OIDS.ipAdEntIfIndex);
                        break;
                    }
                }
            } catch (fallbackErr) {
                console.warn(`[WARN] Falha ao consultar ipAdEntIfIndex com snmpWalk para ifIndex ${id}:`, fallbackErr);
                // Fallback com getSnmpData
                console.log(`[INFO] Usando fallback com getSnmpData para ifIndex ${id}`);
                const ipOids = FALLBACK_IPS.map(ip => `${OIDS.ipAdEntIfIndex}.${ip}`);
                try {
                    const ipData = await getSnmpData(device.ip, device.community, ipOids);
                    for (const knownIp of FALLBACK_IPS) {
                        const oid = `${OIDS.ipAdEntIfIndex}.${knownIp}`;
                        if (ipData[oid] === id) {
                            ip = knownIp;
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
            speed: data[oids[2]] ? `${parseInt(data[oids[2]]) / 1000000} Mbps` : "N/A",
            ip: ip || null
        });
    } catch (err) {
        console.error(`[ERROR] Erro na rota /interface/${id}:`, err);
        if (err.status === snmp.ErrorStatus.NoSuchName) {
            return res.status(404).json({ error: `Interface com ifIndex ${id} não encontrada` });
        }
        res.status(500).json({ error: err.message });
    }
});

app.get("/system", (req, res) => {
    const ip = monitoredDevices[0].ip;
    const community = monitoredDevices[0].community;
    const oids = [
        "1.3.6.1.2.1.1.1.0", // sysDescr
        "1.3.6.1.2.1.1.3.0"  // sysUpTime
    ];
    const session = createSession(ip, community);
    session.get(oids, (error, varbinds) => {
        session.close();
        if (error) return res.status(500).json({ error: error.toString() });
        res.json({
            description: varbinds[0].value.toString(),
            uptime: formatUptime(varbinds[1].value)
        });
    });
});


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

setInterval(async () => {clear
    console.log("Coletando dados SNMP...");
    for (const device of monitoredDevices) {
        try {
            const data = await getSnmpData(device.ip, device.community, device.oids);
            monitorData.push({
                timestamp: new Date(),
                ip: device.ip,
                data
            });
        } catch (err) {
            console.error(`Erro no rotador  R4 ${device.ip}: port DOWN`, err.message);
        }
    }
}, 1000);

app.get("/monitor", (req, res) => {
    res.json(monitorData);
});



app.listen(5000, () => {
    console.log("API rodando em http://localhost:5000");
});