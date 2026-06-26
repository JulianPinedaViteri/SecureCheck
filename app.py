from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health_check():
        return jsonify({"status": "SecureCheck API is running"})

@app.route('/scan', methods=['POST'])
def scan_system():
        data = request.get_json()

        if not data:
                return jsonify({"error": "No data provided"}), 400
        
        findings = []
        score = 100

        open_ports = data.get('open_ports', [])
        telnet_enabled = data.get('telnet_enabled', False)
        ftp_enabled = data.get('ftp_enabled', False)
        password_length = data.get('password_length', 0)
        ssh_enabled = data.get('ssh_enabled', True)

        if telnet_enabled:
                findings.append({
                        "rule": "No Telnet",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "detail": "Telnet transmits data in cleartext. Use SSH instead."

                })
                score -= 25

        if ftp_enabled:
                findings.append({
                        "rule": "No FTP",
                        "status": "FAIL",
                        "severity": "MEDIUM",
                        "detail": "FTP transmits credentials in cleartext. Use SFTP instead."
                })
                score -= 15
        
        if password_length < 12:
                findings.append({               
                            "rule": "Password Length >=12",
                            "status": "FAIL",
                            "severity": "HIGH",
                            "detail": f"Password length is {password_length}. Minimum required is 12."
                })
                score -= 25
        
        if not ssh_enabled:
                findings.append({
                        "rule": "SSH Enabled",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "detail": "SSH is disabled. Secure remote access requires SSH to be enabled."
                })
                score -= 20

        if 23 in open_ports:
                findings.append({
                        "rule": "Port 23 Telnet Closed",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "detail": "Port 23 is open. Telnet port should be closed."
                })
                score -= 20 
        
        if 21 in open_ports:
                findings.append({
                    "rule": "Port 21 FTP Closed",
                    "status": "FAIL",
                    "severity": "MEDIUM",
                    "detail": "Port 21 is open. FTP port should be closed or replaced with SFTP."
                })
                score -= 15
        
        overall_status = "PASS" if not findings else "FAIL"

        passing = [{"rule": "All clear", "status": "PASS", "severity": "NONE",
                    "detail": "No issues found."}] if not findings else []
        
        return jsonify({
                "overall_status": overall_status,
                "score": f"{max(score, 0)}/100",
                "findings": findings if findings else passing
        })

if __name__ == '__main__':
        app.run(debug=True)