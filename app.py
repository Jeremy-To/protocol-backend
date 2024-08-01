import sys
import subprocess
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
import tempfile
import os

app = Flask(__name__)
CORS(app)


def analyze_pcap(file_path):
    protocol_stats = defaultdict(lambda: {
                                 'packet_count': 0, 'data_transferred': 0, 'client_to_server_bytes': 0, 'server_to_client_bytes': 0})

    # Ensure tshark is installed
    try:
        subprocess.run(['tshark', '-v'], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        return {"error": "tshark is not installed or not found in PATH."}

    # Run tshark to get the protocol, length, source IP, destination IP, source port, and destination port of each packet
    tshark_cmd = [
        'tshark',
        '-r', file_path,
        '-T', 'fields',
        '-e', '_ws.col.Protocol',
        '-e', 'frame.len',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport'
    ]
    process = subprocess.Popen(
        tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        return {"error": f"Error running tshark: {stderr.decode().strip()}"}

    total_packets = 0
    for line in stdout.decode().splitlines():
        if not line:
            continue
        fields = line.split('\t')
        if len(fields) != 6:
            continue
        protocol, length, src_ip, dst_ip, src_port, dst_port = fields
        length = int(length)
        protocol_stats[protocol]['packet_count'] += 1
        protocol_stats[protocol]['data_transferred'] += length
        total_packets += 1

        # Determine direction (client to server or server to client)
        if src_port and dst_port:
            if int(src_port) > int(dst_port):
                protocol_stats[protocol]['client_to_server_bytes'] += length
            else:
                protocol_stats[protocol]['server_to_client_bytes'] += length

    # Prepare the results
    results = {
        "total_packets": total_packets,
        "protocols": {}
    }

    for protocol, stats in protocol_stats.items():
        results["protocols"][protocol] = {
            "packet_count": stats['packet_count'],
            "packet_percentage": (stats['packet_count'] / total_packets) * 100,
            "total_mb": stats['data_transferred'] / (1024 * 1024),
            "client_to_server_mb": stats['client_to_server_bytes'] / (1024 * 1024),
            "server_to_client_mb": stats['server_to_client_bytes'] / (1024 * 1024)
        }

    return results


@app.route('/analyze', methods=['POST'])
def analyze_pcap_route():
    if 'pcap' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['pcap']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file:
        # Create a temporary file to store the uploaded PCAP
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        file.save(temp_file.name)

        try:
            # Analyze the PCAP file
            results = analyze_pcap(temp_file.name)
            return jsonify(results)

        except Exception as e:
            return jsonify({"error": str(e)}), 500

        finally:
            # Clean up the temporary file
            temp_file.close()
            os.unlink(temp_file.name)

    return jsonify({"error": "Unknown error occurred"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
