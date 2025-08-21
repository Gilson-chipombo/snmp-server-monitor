const express = require("express");
const snmp = require("net-snmp");

const app = express();
app.use(express.json());

let monitorData = [];

function createSession(ip, community) {
    return snmp.createSession(ip, community);
}


function formatUptime(ticks) {
    let seconds = Math.floor(ticks / 100);
    let days = Math.floor(seconds / 86400);
    seconds %= 86400;
    let hours = Math.floor(seconds / 3600);
    seconds %= 3600;
    let minutes = Math.floor(seconds / 60);
    seconds %= 60;
    return `${days}d ${hours}h ${minutes}m ${seconds}s`;
}


function getSnmpData(ip, community, oids) {
    return new Promise((resolve, reject) => {
        const session = createSession(ip, community);
        session.get(oids, (error, varbinds) => {
            session.close();
            if (error) {
                reject(error);
            } else {
                const result = {};
                varbinds.forEach((vb) => {
                    result[vb.oid] = vb.value.toString();
                });
                resolve(result);
            }
        });
    });
}

const monitoredDevices = [
    {
        ip: "192.168.220.134",
        community: "public",
        oids: [
           "1.3.6.1.2.1.1.1.0", // sysDescr
            "1.3.6.1.2.1.1.3.0", // sysUpTime
            "1.3.6.1.4.1.9.2.1.56.0", // CPU 5 sec
            "1.3.6.1.4.1.9.2.1.57.0", // CPU 1 min
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
            "1.3.6.1.4.1.9.2.1.56.0", // CPU 5 sec
            "1.3.6.1.4.1.9.2.1.57.0", // CPU 1 min
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
            "1.3.6.1.4.1.9.2.1.56.0", // CPU 5 sec
            "1.3.6.1.4.1.9.2.1.57.0", // CPU 1 min
            "1.3.6.1.4.1.9.2.1.58.0", // CPU 5 min
            "1.3.6.1.4.1.9.2.1.8.0",  // Memória livre
            "1.3.6.1.4.1.9.2.1.9.0",  // Memória usada
            "1.3.6.1.2.1.2.2.1.8.2"   // ifOperStatus (Interface 2)
        ]
    }
];

app.post("/snmp", async (req, res) => {
    const { ip, community, oids } = req.body;
    if (!ip || !community || !oids) {
        return res.status(400).json({ error: "Parâmetros inválidos" });
    }
    try {
        const data = await getSnmpData(ip, community, oids);
        res.json({ ip, data });
    } catch (err) {
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

/*
app.get("/interfaces", async (req, res) => {
    const ip = monitoredDevices[0].ip;
    const community = monitoredDevices[0].community;
    const session = createSession(ip, community);
    const oidName = "1.3.6.1.2.1.2.2.1.2";  // ifDescr
    const oidStatus = "1.3.6.1.2.1.2.2.1.8"; // ifOperStatus

    try {
        const [nameVarbinds, statusVarbinds] = await Promise.all([
            getSubtree(session, oidName),
            getSubtree(session, oidStatus)
        ]);

        let interfaces = {};
        nameVarbinds.forEach((vb) => {
            const id = vb.oid.split(".").pop();
            if (!interfaces[id]) interfaces[id] = {};
            interfaces[id].name = vb.value.toString();
        });

        statusVarbinds.forEach((vb) => {
            const id = vb.oid.split(".").pop();
            if (!interfaces[id]) interfaces[id] = {};
            interfaces[id].status = parseInt(vb.value) === 1 ? "UP" : "DOWN";
        });

        const result = Object.keys(interfaces).map(id => ({
            id,
            name: interfaces[id].name,
            status: interfaces[id].status
        }));
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.toString() });
    } finally {
        session.close();
    }
});*/
/*
app.get("/interface/:id", (req, res) => {
    const id = req.params.id;
    const ip = monitoredDevices[0].ip;
    const community = monitoredDevices[0].community;
    const oids = [
        `1.3.6.1.2.1.2.2.1.2.${id}`, // ifDescr
        `1.3.6.1.2.1.2.2.1.8.${id}`, // ifOperStatus
        `1.3.6.1.2.1.2.2.1.5.${id}`  // ifSpeed
    ];
    const session = createSession(ip, community);
    session.get(oids, (error, varbinds) => {
        session.close();
        if (error) return res.status(500).json({ error: error.toString() });
        res.json({
            id,
            name: varbinds[0].value.toString(),
            status: varbinds[1].value === 1 ? "up" : "down",
            speed: `${varbinds[2].value / 1_000_000} Mbps`
        });
    });
});
*/


const OIDS = {
    ifDescr: "1.3.6.1.2.1.2.2.1.2",      // Nome da interface
    ifOperStatus: "1.3.6.1.2.1.2.2.1.8", // Estado da interface
    ipAdEntIfIndex: "1.3.6.1.2.1.4.20.1.2", // Mapeamento IP -> Interface
    ipAdEntAddr: "1.3.6.1.2.1.4.20.1.1"     // Endereços IP
};

const device = { ip: "192.168.220.134", community: "public" };

function snmpWalk(ip, community, oid) {
    return new Promise((resolve, reject) => {
        const session = snmp.createSession(ip, community);
        const results = {};

        session.subtree(oid, (varbind) => {
            results[varbind.oid] = varbind.value.toString();
        }, (error) => {
            session.close();
            if (error) reject(error);
            else resolve(results);
        });
    });
}

/*
app.get("/interfaces", async (req, res) => {
    try {
        const [ifDescr, ifOperStatus, ipAdEntIfIndex, ipAdEntAddr] = await Promise.all([
            snmpWalk(device.ip, device.community, OIDS.ifDescr),
            snmpWalk(device.ip, device.community, OIDS.ifOperStatus),
            snmpWalk(device.ip, device.community, OIDS.ipAdEntIfIndex),
            snmpWalk(device.ip, device.community, OIDS.ipAdEntAddr)
        ]);

        // Montar tabela IP -> InterfaceIndex
        const ipMap = {};
        for (const [oid, ifIndex] of Object.entries(ipAdEntIfIndex)) {
            const ip = oid.split(".").slice(-4).join(".");
            ipMap[ifIndex] = ip;
        }

        // Montar resposta final
        const interfaces = [];
        for (const [oid, name] of Object.entries(ifDescr)) {
            const ifIndex = oid.split(".").pop();
            interfaces.push({
                name,
                ip: ipMap[ifIndex] || null,
                status: ifOperStatus[`${OIDS.ifOperStatus}.${ifIndex}`] === "1" ? "up" : "down"
            });
        }

        res.json(interfaces);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});*/








setInterval(async () => {
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

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});

