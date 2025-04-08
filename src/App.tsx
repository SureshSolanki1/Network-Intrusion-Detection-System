import React, { useState, useEffect, useCallback } from 'react';
import { Shield, AlertTriangle, Activity, Database, AlertCircle, CheckCircle, Upload, X } from 'lucide-react';
import Papa from 'papaparse';

interface PacketData {
  timestamp: string;
  sourceIP: string;
  destinationIP: string;
  protocol: string;
  port: number;
  length: number;
  info: string;
  isThreat: boolean;
  threatType?: string;
}

interface Alert {
  id: number;
  type: string;
  source: string;
  timestamp: string;
  packetDetails: PacketData;
}

// Threat detection rules
const detectThreats = (packet: any): { isThreat: boolean; threatType?: string } => {
  const info = packet.info?.toLowerCase() || '';
  const length = parseInt(packet.length) || 0;
  const protocol = packet.protocol?.toLowerCase() || '';

  if (length > 1500) {
    return { isThreat: true, threatType: 'Possible DDoS Attack (Large Packet)' };
  }
  
  if (info.includes('syn') && info.includes('scan')) {
    return { isThreat: true, threatType: 'Port Scan Detected' };
  }

  if (protocol === 'tcp' && info.includes('reset')) {
    return { isThreat: true, threatType: 'TCP Reset Attack' };
  }

  if (info.includes('malform') || info.includes('malicious')) {
    return { isThreat: true, threatType: 'Malformed Packet' };
  }

  if (protocol === 'http' && (
    info.includes('sql') || 
    info.includes('select') || 
    info.includes('union') ||
    info.includes('insert')
  )) {
    return { isThreat: true, threatType: 'Possible SQL Injection' };
  }

  return { isThreat: false };
};

function PacketDetailsModal({ packet, onClose }: { packet: PacketData; onClose: () => void }) {
  if (!packet) return null;

  const riskAnalysis = [
    { title: 'Large Packet Size', risk: packet.length > 1500 ? 'High' : 'Low', 
      description: packet.length > 1500 ? 'Unusually large packet size could indicate DDoS attack' : 'Normal packet size' },
    { title: 'Protocol Security', risk: packet.protocol === 'HTTP' ? 'Medium' : 'Low',
      description: packet.protocol === 'HTTP' ? 'Unencrypted protocol, vulnerable to MITM attacks' : 'Protocol security adequate' },
    { title: 'Port Analysis', 
      risk: [20, 21, 22, 23, 25, 53, 80, 443, 3306, 3389].includes(packet.port) ? 'Medium' : 'Low',
      description: 'Common port - potential target for attacks' },
  ];

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-2xl font-bold text-gray-800">Packet Details</h2>
            <button onClick={onClose} className="text-gray-500 hover:text-gray-700">
              <X className="w-6 h-6" />
            </button>
          </div>

          <div className="space-y-6">
            {/* Basic Information */}
            <div>
              <h3 className="text-lg font-semibold mb-3 text-gray-700">Basic Information</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm font-medium text-gray-500">Timestamp</p>
                  <p className="text-gray-900">{new Date(packet.timestamp).toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500">Protocol</p>
                  <p className="text-gray-900">{packet.protocol}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500">Source IP</p>
                  <p className="text-gray-900">{packet.sourceIP}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500">Destination IP</p>
                  <p className="text-gray-900">{packet.destinationIP}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500">Port</p>
                  <p className="text-gray-900">{packet.port}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500">Packet Length</p>
                  <p className="text-gray-900">{packet.length} bytes</p>
                </div>
              </div>
            </div>

            {/* Threat Information */}
            <div>
              <h3 className="text-lg font-semibold mb-3 text-gray-700">Threat Analysis</h3>
              <div className="bg-gray-50 rounded-lg p-4">
                <div className="flex items-center mb-3">
                  {packet.isThreat ? (
                    <AlertTriangle className="w-5 h-5 text-red-500 mr-2" />
                  ) : (
                    <CheckCircle className="w-5 h-5 text-green-500 mr-2" />
                  )}
                  <span className={`font-semibold ${packet.isThreat ? 'text-red-700' : 'text-green-700'}`}>
                    {packet.isThreat ? packet.threatType : 'No Immediate Threats Detected'}
                  </span>
                </div>
                <p className="text-sm text-gray-600">
                  {packet.info || 'No additional information available'}
                </p>
              </div>
            </div>

            {/* Risk Assessment */}
            <div>
              <h3 className="text-lg font-semibold mb-3 text-gray-700">Risk Assessment</h3>
              <div className="space-y-3">
                {riskAnalysis.map((analysis, index) => (
                  <div key={index} className="bg-gray-50 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-gray-700">{analysis.title}</span>
                      <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                        analysis.risk === 'High' ? 'bg-red-100 text-red-800' :
                        analysis.risk === 'Medium' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-green-100 text-green-800'
                      }`}>
                        {analysis.risk} Risk
                      </span>
                    </div>
                    <p className="text-sm text-gray-600">{analysis.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function App() {
  const [trafficLogs, setTrafficLogs] = useState<PacketData[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState({
    totalPackets: 0,
    threats: 0,
    normalTraffic: 0,
  });
  const [isSimulationActive, setIsSimulationActive] = useState(true);
  const [selectedPacket, setSelectedPacket] = useState<PacketData | null>(null);

  const handleFileUpload = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsSimulationActive(false); // Stop simulation when analyzing real data
    
    Papa.parse(file, {
      complete: (results) => {
        const packets: PacketData[] = results.data
          .slice(1) // Skip header row
          .map((row: any) => {
            const packet = {
              timestamp: row[0] || new Date().toISOString(),
              sourceIP: row[2] || 'unknown',
              destinationIP: row[3] || 'unknown',
              protocol: row[4] || 'unknown',
              port: parseInt(row[5]) || 0,
              length: parseInt(row[6]) || 0,
              info: row[7] || '',
            };

            const threatAnalysis = detectThreats(packet);
            return {
              ...packet,
              ...threatAnalysis,
            };
          })
          .filter((packet: PacketData) => packet.sourceIP !== 'unknown');

        const threats = packets.filter(packet => packet.isThreat);
        
        setTrafficLogs(packets.slice(0, 10));
        setAlerts(threats.map(threat => ({
          id: Date.now(),
          type: threat.threatType || '',
          source: threat.sourceIP,
          timestamp: threat.timestamp,
          packetDetails: threat,
        })).slice(0, 5));
        
        setStats({
          totalPackets: packets.length,
          threats: threats.length,
          normalTraffic: packets.length - threats.length,
        });
      },
      header: true,
      skipEmptyLines: true,
    });
  }, []);

  useEffect(() => {
    if (!isSimulationActive) return;

    const interval = setInterval(() => {
      const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS'];
      const ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25', '192.168.1.200'];
      const ports = [80, 443, 8080, 22, 3306];
      const threats = ['SQL Injection', 'DDoS Attack', 'Port Scan', 'Malware Traffic'];
      
      const newTraffic: PacketData = {
        timestamp: new Date().toISOString(),
        sourceIP: ips[Math.floor(Math.random() * ips.length)],
        destinationIP: ips[Math.floor(Math.random() * ips.length)],
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        port: ports[Math.floor(Math.random() * ports.length)],
        length: Math.floor(Math.random() * 1500) + 64,
        info: '',
        isThreat: Math.random() < 0.2,
        threatType: threats[Math.floor(Math.random() * threats.length)],
      };

      setTrafficLogs(prev => [newTraffic, ...prev].slice(0, 10));
      
      if (newTraffic.isThreat) {
        setAlerts(prev => [{
          id: Date.now(),
          type: newTraffic.threatType || '',
          source: newTraffic.sourceIP,
          timestamp: newTraffic.timestamp,
          packetDetails: newTraffic,
        }, ...prev].slice(0, 5));
      }

      setStats(prev => ({
        totalPackets: prev.totalPackets + 1,
        threats: prev.threats + (newTraffic.isThreat ? 1 : 0),
        normalTraffic: prev.normalTraffic + (newTraffic.isThreat ? 0 : 1),
      }));
    }, 2000);

    return () => clearInterval(interval);
  }, [isSimulationActive]);

  return (
    <div className="min-h-screen bg-gray-100">
  <nav className="bg-indigo-600 text-white p-4">
    <div className="container mx-auto flex justify-center items-center">
      <Shield className="w-8 h-8 mr-2" />
      <h1 className="text-2xl font-bold">Network Intrusion Detection System</h1>
    </div>
  </nav>
        
        <main className="container mx-auto p-4">
        {/* File Upload */}
        <div className="bg-white rounded-lg shadow p-6 mb-6">
          <div className="flex items-center mb-4">
            <Upload className="w-6 h-6 text-indigo-500 mr-2" />
            <h2 className="text-xl font-semibold">Upload CSV captured by Wireshark</h2>
          </div>
          <div className="flex items-center space-x-4">
            <input
              type="file"
              accept=".csv"
              onChange={handleFileUpload}
              className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-indigo-50 file:text-indigo-700 hover:file:bg-indigo-100"
            />
            <button
              onClick={() => setIsSimulationActive(prev => !prev)}
              className={`px-4 py-2 rounded-full text-sm font-semibold ${
                isSimulationActive 
                  ? 'bg-red-50 text-red-700 hover:bg-red-100' 
                  : 'bg-green-50 text-green-700 hover:bg-green-100'
              }`}
            >
              {isSimulationActive ? 'Stop Simulation' : 'Start Simulation'}
            </button>
          </div>
        </div>

        {/* Dashboard Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <Database className="w-6 h-6 text-blue-500 mr-2" />
              <h2 className="text-xl font-semibold">Total Packets</h2>
            </div>
            <p className="text-3xl font-bold mt-2">{stats.totalPackets}</p>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <AlertCircle className="w-6 h-6 text-red-500 mr-2" />
              <h2 className="text-xl font-semibold">Threats Detected</h2>
            </div>
            <p className="text-3xl font-bold mt-2">{stats.threats}</p>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center">
              <CheckCircle className="w-6 h-6 text-green-500 mr-2" />
              <h2 className="text-xl font-semibold">Normal Traffic</h2>
            </div>
            <p className="text-3xl font-bold mt-2">{stats.normalTraffic}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Traffic Monitor */}
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center mb-4">
              <Activity className="w-6 h-6 text-blue-500 mr-2" />
              <h2 className="text-xl font-semibold">Live Traffic Monitor</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead>
                  <tr className="bg-gray-50">
                    <th className="px-4 py-2 text-left">Time</th>
                    <th className="px-4 py-2 text-left">Source IP</th>
                    <th className="px-4 py-2 text-left">Protocol</th>
                    <th className="px-4 py-2 text-left">Port</th>
                    <th className="px-4 py-2 text-left">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {trafficLogs.map((log, index) => (
                    <tr key={index} className={`border-t ${log.isThreat ? 'bg-red-50' : ''}`}>
                      <td className="px-4 py-2">{new Date(log.timestamp).toLocaleTimeString()}</td>
                      <td className="px-4 py-2">{log.sourceIP}</td>
                      <td className="px-4 py-2">{log.protocol}</td>
                      <td className="px-4 py-2">{log.port}</td>
                      <td className="px-4 py-2">
                        {log.isThreat ? (
                          <span className="text-red-500 flex items-center">
                            <AlertTriangle className="w-4 h-4 mr-1" />
                            Threat
                          </span>
                        ) : (
                          <span className="text-green-500 flex items-center">
                            <CheckCircle className="w-4 h-4 mr-1" />
                            Normal
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Threat Alerts */}
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center mb-4">
              <AlertTriangle className="w-6 h-6 text-red-500 mr-2" />
              <h2 className="text-xl font-semibold">Recent Alerts</h2>
            </div>
            <div className="space-y-4">
              {alerts.map((alert) => (
                <div 
                  key={alert.id} 
                  className="bg-red-50 border border-red-200 rounded-lg p-4 cursor-pointer hover:bg-red-100 transition-colors"
                  onClick={() => setSelectedPacket(alert.packetDetails)}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-red-700">{alert.type}</span>
                    <span className="text-sm text-gray-500">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 mt-1">
                    Suspicious activity detected from IP: {alert.source}
                  </p>
                </div>
              ))}
              {alerts.length === 0 && (
                <p className="text-gray-500 text-center py-4">No recent alerts</p>
              )}
            </div>
          </div>
        </div>
      </main>

      {selectedPacket && (
        <PacketDetailsModal
          packet={selectedPacket}
          onClose={() => setSelectedPacket(null)}
        />
      )}
    </div>
  );
}

export default App;