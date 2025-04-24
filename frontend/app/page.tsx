"use client";
import { useEffect, useRef, useState } from "react";
import { EventsEmit, EventsOn } from "../wailsjs/runtime/runtime";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";

export default function Home() {
  const [tcpCollectorOn, setTcpCollectorOn] = useState(false);
  const [udpCollectorOn, setUdpCollectorOn] = useState(false);
  const [icmpCollectorOn, setIcmpCollectorOn] = useState(false);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [blockedIPs, setBlockedIPs] = useState<any[]>([]);

  const blockedIPsRef = useRef<any[]>([]);

  // Sync ref with state
  useEffect(() => {
    blockedIPsRef.current = blockedIPs;
  }, [blockedIPs]);

  // Emit avoidBlocking based on collectors' state
  useEffect(() => {
    const shouldAvoidBlocking =
      tcpCollectorOn || udpCollectorOn || icmpCollectorOn;
    EventsEmit("avoidBlocking", shouldAvoidBlocking ? "true" : "false");
  }, [tcpCollectorOn, udpCollectorOn, icmpCollectorOn]);

  // Update alert status or add new alert
  const updateAlertStatus = (newAlert: any) => {
    const now = Date.now();

    setAlerts((prevAlerts) => {
      const index = prevAlerts.findIndex(
        (alert) =>
          alert.Attacker_ip === newAlert.Attacker_ip &&
          alert.Target_port === newAlert.Target_port &&
          alert.Method === newAlert.Method &&
          alert.Protocol === newAlert.Protocol
      );

      if (index !== -1) {
        return prevAlerts.map((alert, i) =>
          i === index ? { ...alert, Status: "active", lastSeen: now } : alert
        );
      }

      return [
        ...prevAlerts,
        {
          ...newAlert,
          Status: "active",
          lastSeen: now,
          startTime: now,
        },
      ];
    });
  };

  // Passive alerts logic
  const setInactiveAlerts = () => {
    const now = Date.now();
    setAlerts((prevAlerts) =>
      prevAlerts.map((alert) => {
        const isOld = now - alert.lastSeen > 10000;
        return isOld ? { ...alert, Status: "passive" } : alert;
      })
    );
  };

  // Shared useEffect for setting interval and handling "alert"
  useEffect(() => {
    const interval = setInterval(setInactiveAlerts, 1000);

    const unbindAlert = EventsOn("alert", (data: any) => {
      console.log("Alert data:", data);
      console.log("Blocked IPs (ref):", blockedIPsRef.current);

      if (blockedIPsRef.current.includes(data.Attacker_ip)) return;
      updateAlertStatus(data);
    });

    return () => {
      clearInterval(interval);
      unbindAlert();
    };
  }, []);

  // Handle "block" events
  useEffect(() => {
    const unbindBlock = EventsOn("block", (data: any) => {
      updateBlockedIPs(data);
    });

    return () => {
      unbindBlock();
    };
  }, []);

  // Add IP to blocked list if not already blocked
  const updateBlockedIPs = (ip: string) => {
    setBlockedIPs((prev) => {
      if (!prev.includes(ip)) return [...prev, ip];
      return prev;
    });
  };

  // Unblock a specific IP
  const unblockIP = (attackerIP: string) => {
    EventsEmit("unblock", attackerIP);
    setBlockedIPs((prev) => prev.filter((ip) => ip !== attackerIP));
  };

  // Function to format time in UTC+03:00 (Asia/Riyadh)
  const formatStartTime = (timestamp: number) => {
    return new Date(timestamp).toLocaleString("en-US", {
      timeZone: "Asia/Riyadh",
      hour12: false, // 24-hour format
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  return (
    <main className="p-6 space-y-6 bg-gray-50 min-h-screen">
      <div className="flex flex-col md:flex-row items-center justify-between gap-4">
        <h1 className="text-4xl font-bold text-center md:text-left">
          IPS Monitoring
        </h1>

        {(tcpCollectorOn || udpCollectorOn || icmpCollectorOn) && (
          <div className="p-3 bg-yellow-100 border border-yellow-400 text-yellow-800 rounded-md text-sm text-center md:text-left">
            ⚠️ No automatic IP Blocking while in collector mode.
          </div>
        )}
      </div>

      {/* CSV Data Collector Status Table with Switches */}
      <div className="gap-6 mt-6">
        <Card>
          <CardHeader>
            <CardTitle>CSV Data Collector</CardTitle>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <table className="w-full table-auto border-collapse text-sm">
              <thead>
                <tr className="bg-gray-100 text-left">
                  <th className="p-2">TCP</th>
                  <th className="p-2">UDP</th>
                  <th className="p-2">ICMP</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-t">
                  <td className="p-2">
                    <div className="flex items-center space-x-2">
                      <Switch
                        id="tcp-collector-mode"
                        checked={tcpCollectorOn}
                        onCheckedChange={() => {
                          EventsEmit("csv", "tcp");
                          setTcpCollectorOn((prev) => !prev);
                        }}
                      />
                      <span
                        className={`font-semibold ${
                          tcpCollectorOn ? "text-green-600" : "text-gray-500"
                        }`}></span>
                    </div>
                  </td>

                  <td className="p-2">
                    <div className="flex items-center space-x-2">
                      <Switch
                        id="udp-collector-mode"
                        checked={udpCollectorOn}
                        onCheckedChange={() => {
                          setUdpCollectorOn((prev) => !prev);
                          EventsEmit("csv", "udp");
                        }}
                      />
                      <span
                        className={`font-semibold ${
                          udpCollectorOn ? "text-blue-600" : "text-gray-500"
                        }`}></span>
                    </div>
                  </td>

                  <td className="p-2">
                    <div className="flex items-center space-x-2">
                      <Switch
                        id="icmp-collector-mode"
                        checked={icmpCollectorOn}
                        onCheckedChange={() => {
                          EventsEmit("csv", "icmp");
                          setIcmpCollectorOn((prev) => !prev);
                        }}
                      />
                      <span
                        className={`font-semibold ${
                          icmpCollectorOn ? "text-red-600" : "text-gray-500"
                        }`}></span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </CardContent>
        </Card>
      </div>

      {/* Alert Table */}
      <div className="gap-6 mt-6">
        <Card>
          <CardHeader>
            <CardTitle>Attack Info</CardTitle>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <table className="w-full table-auto border-collapse text-sm">
              <thead>
                <tr className="bg-gray-100 text-left">
                  <th className="p-2">Method</th>
                  <th className="p-2">Protocol</th>
                  <th className="p-2">Attacker IP</th>
                  <th className="p-2">Target Port</th>
                  <th className="p-2">Message</th>
                  <th className="p-2">Status</th>
                  <th className="p-2">Time</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert, index) => (
                  <tr key={index} className="border-t">
                    <td className="p-2">{alert.Method}</td>
                    <td className="p-2">{alert.Protocol}</td>
                    <td className="p-2">{alert.Attacker_ip}</td>
                    <td className="p-2">{alert.Target_port}</td>
                    <td className="p-2">{alert.Message}</td>
                    <td className="p-2">
                      <span
                        className={`inline-block w-3 h-3 rounded-full ${
                          alert.Status === "active"
                            ? "bg-green-500"
                            : "bg-red-500"
                        }`}
                        title={alert.Status}
                      />
                    </td>
                    <td className="p-2">
                      {alert.startTime ? formatStartTime(alert.startTime) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      </div>

      {/* Blocked IPs Table */}
      <div className="gap-6 mt-6">
        <Card>
          <CardHeader>
            <CardTitle>Blocked IPs</CardTitle>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <table className="w-full table-auto border-collapse text-sm">
              <thead>
                <tr className="bg-gray-100 text-left">
                  <th className="p-2">Attacker IP</th>
                  <th className="p-2">Action</th>
                </tr>
              </thead>
              <tbody>
                {blockedIPs.map((ip, index) => (
                  <tr key={index} className="border-t">
                    <td className="p-2">{ip}</td>
                    <td className="p-2">
                      <button
                        onClick={() => unblockIP(ip)}
                        className="text-red-600">
                        Unblock
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
