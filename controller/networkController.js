
import { PythonService } from '../services/PythonService.js'


/*
ex:-python script.py google.com

input require 1 
1- domain or ip (optinal  choose one from them ) */

const dnsScan = async (req, res) => {
    try {
        const domain = req.body.domain || req.query.domain
        console.log(req.body)
        console.log(req.query)
        
        console.log(`Domain: ${domain}`)
        
        if (!domain) {
            return res.status(400).send('Domain parameter is required');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('DNS Hostname Scanning', [domain])
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('DNS scan failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

/*
format :- python script.py <target> <protocol> <ports>
ex:-python script.py google.com tcp 80,443,22
*/
const firewallTest = async (req, res) => {
    try {
        const { target, protocol, ports } = req.body || req.query
        
        if (!target || !protocol || !ports) {
            return res.status(400).send('Target, protocol, and ports parameters are required');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('Firewall and ACL Testing', [target, protocol, ports]);
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('Firewall test failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

// input :_ target ip range <CIDR_RANGE> , ex:-python network_scanner.py 192.168.1.0/24
const ipScan = async (req, res) => {
    try {
        const  cidr  = req.body?.cidr || req.query?.cidr
        
        if (!cidr) {
            return res.status(400).send('CIDR parameter is required');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('IP Scanning', [cidr]);
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('IP scan failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

/*input require 2  
1- ip or domain (optinal you can write ip or domain )
2- port range  */

const portScan = async (req, res) => {
    try {
        const { target, range } = req.body || req.query
        console.log(req.query)
        
        if (!target || !range) {
            return res.status(400).send('Target and range parameters are required');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('Port Scanning', [target, range]);
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('Port scan failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

// input :- ip or domain 
const protocolScan = async (req, res) => {
    try {
        const { target } = req.body || req.query;
        
        if (!target) {
            return res.status(400).send('Target parameter is required');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('Protocol Analysis', [target]);
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('Protocol scan failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

/*format:- python service_scanner.py <target>
format 2:- python service_scanner.py <target> --version-detection

ex :- python service_scanner.py example.com

input 2 :- 
1 - ip or domain 
2- enable service version detection (optinal click checkbox)*/

const serviceDetect = async (req, res) => {
    try {
        const { target, versionDetection } = req.body || req.query

        if (!target) {
            return res.status(400).send('Target parameter is required');
        }

        const args = [target];
        if (versionDetection === 'true') {
            args.push('--version-detection')
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('Service Detection', args)
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('Service detection failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

/*
format:- python segmentation_scanner.py <subnet> <vlan_id>
ex:-python segmentation_scanner.py 192.168.1.0/24 10
input :- subnet or vlan identifier */
const subnetScan = async (req, res) => {
    try {
        const { subnet, vlan } = req.body || req.query
        
        if (!subnet || !vlan) {
            return res.status(400).send('Subnet and VLAN parameters are required');
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('Subnet and VLAN Scanning', [subnet, vlan])
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('Subnet scan failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

const latencyTest = async (req, res) => {
    try {
        const { target, count } = req.body || req.query
        
        if (!target) {
            return res.status(400).send('Target parameter is required');
        }

        const args = [target]
        if (count) {
            args.push('-c', count)
        }

        const pythonService = new PythonService();
        const rawOutput = await pythonService.executeScript('Latency Testing', args)
        
        res.setHeader('Content-Type', 'text/plain');
        return res.send(rawOutput);
    } catch (error) {
        console.error('Latency test failed:', error);
        res.setHeader('Content-Type', 'text/plain');
        return res.status(500).send(`Error: ${error.message}`);
    }
};

export {
    dnsScan,
    firewallTest,
    ipScan,
    portScan,
    protocolScan,
    serviceDetect,
    subnetScan,
    latencyTest
}








































































































// const ipscanController = async (req, res) => {
//     try {
//         const { ip } = req.query || req.body?.ip || '192.165.1.1/24'
//         const name = req.params.name || 'Service Detection'
//         console.log(`IP: ${ip}, Name: ${name}`)
//         const range = '20-80'
        
//         if(!name || !ip) {
//             return res.status(400).send('Missing required parameters: name or ip');
//         }

//         const pythonService = new PythonService()
        
//         const rawOutput = await pythonService.executeScript(name , [ip , range])
        
//         // Return the complete raw output exactly as from terminal
//         res.setHeader('Content-Type', 'text/plain')
//         return res.send(rawOutput)

//     } catch (error) {
//         console.error('Scan failed:', error)
        
//         // Return error output in same format
//         res.setHeader('Content-Type', 'text/plain')
//         return res.status(500).send(`Error: ${error.message}`)
//     }
// };
