const snmp = require("net-snmp");

const session = snmp.createSession("192.168.220.134", "public");

const oid = "1.3.6.1.2.1.1.1.0";

session.get([oid], (error, varbinds) => {
    if (error) {
        console.error(error);
    } else {
        varbinds.forEach(vb => {
            if (snmp.isVarbindError(vb))
                console.error(snmp.varbindError(vb));
            else
                console.log(vb.oid + " = " + vb.value.toString());
        });
    }
    session.close();
});

