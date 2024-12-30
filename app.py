from flask import Flask, render_template, request, Response, jsonify
import nmap
import ipaddress
import requests
import json
import time
import threading

app = Flask(__name__)

def is_astra_cesbo(ip, port):
   try:
      url = f"http://{ip}:{port}"
      response = requests.get(url, timeout=2)
      if response.status_code == 200:
         # Check for Astra-specific indicators in the response
         html_content = response.text.lower()
         title = response.text.split('<title>')[1].split('</title>')[0] if '<title>' in response.text else ''
         
         astra_indicators = [
             'astra',
             'cesbo',
             'astra control panel',
             'astra relay'
         ]
         
         if any(indicator in html_content.lower() for indicator in astra_indicators):
             return {
                 "found": True,
                 "type": "Astra " + ("Control Panel" if "control panel" in title.lower() else "Relay"),
                 "url": url,
                 "title": title
             }
             
      return {"found": False}
   except requests.exceptions.RequestException as e:
     return {"found": False}
   except Exception as e:
     return {"found": False}

def validate_ip(ip):
    try:
        # Check if IP is valid
        ip_obj = ipaddress.ip_address(ip)
        # Convert to string to ensure proper format
        return str(ip_obj)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip}")

def get_ip_range(form_data):
    range_type = form_data.get('range_type')
    
    if range_type == 'single':
        single_ip = form_data.get('single_ip', '').strip()
        if not single_ip:
            raise ValueError("IP address cannot be empty")
        return [validate_ip(single_ip)]
        
    elif range_type == 'cidr':
        cidr_range = form_data.get('cidr_range', '').strip()
        if not cidr_range:
            raise ValueError("CIDR range cannot be empty")
        try:
            network = ipaddress.ip_network(cidr_range, strict=False)
            if network.num_addresses > 256:
                raise ValueError("CIDR range too large. Maximum 256 addresses allowed")
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            raise ValueError(f"Invalid CIDR range: {str(e)}")
            
    elif range_type == 'range':
        start_ip = form_data.get('start_ip', '').strip()
        end_ip = form_data.get('end_ip', '').strip()
        
        if not start_ip or not end_ip:
            raise ValueError("Start and End IP addresses cannot be empty")
            
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            
            if int(end) < int(start):
                raise ValueError("End IP must be greater than Start IP")
                
            if int(end) - int(start) > 255:
                raise ValueError("IP range too large. Maximum 256 addresses allowed")
                
            return [str(ipaddress.ip_address(ip)) for ip in range(int(start), int(end) + 1)]
        except ValueError as e:
            raise ValueError(f"Invalid IP range: {str(e)}")
            
    elif range_type == 'list':
        ip_list = form_data.get('ip_list', '').strip()
        if not ip_list:
            raise ValueError("IP list cannot be empty")
            
        result = []
        errors = []
        
        # Split by common separators (newline, comma, space)
        items = [item.strip() for item in ip_list.replace(',', '\n').split('\n') if item.strip()]
        
        for item in items:
            try:
                if '/' in item:  # CIDR notation
                    network = ipaddress.ip_network(item, strict=False)
                    if network.num_addresses > 256:
                        errors.append(f"CIDR {item} too large (max 256 addresses)")
                        continue
                    result.extend([str(ip) for ip in network.hosts()])
                elif '-' in item:  # Range notation
                    start, end = map(str.strip, item.split('-'))
                    start_ip = ipaddress.ip_address(start)
                    end_ip = ipaddress.ip_address(end)
                    if int(end_ip) < int(start_ip):
                        errors.append(f"Invalid range {item}: end IP less than start IP")
                        continue
                    if int(end_ip) - int(start_ip) > 255:
                        errors.append(f"Range {item} too large (max 256 addresses)")
                        continue
                    result.extend([str(ipaddress.ip_address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)])
                else:  # Single IP
                    result.append(validate_ip(item))
            except ValueError as e:
                errors.append(f"Invalid IP/Range: {item}")
                
        if not result and errors:
            raise ValueError("No valid IPs found. Errors: " + "; ".join(errors))
        
        if errors:
            output_queue.put("Warnings:\n" + "\n".join(errors) + "\n")
            
        return list(set(result))  # Remove duplicates
            
    return []

def get_scan_arguments(form_data):
    args = []
    
    # Timing template
    speed = form_data.get('scan_speed', 'normal')
    speed_map = {
        'paranoid': '-T0', 'sneaky': '-T1', 'polite': '-T2',
        'normal': '-T3', 'aggressive': '-T4', 'insane': '-T5'
    }
    args.append(speed_map.get(speed, '-T3'))
    
    # Skip host discovery if selected
    if form_data.get('skip_discovery') == 'on':
        args.append('-Pn')
    
    # Service detection
    if form_data.get('service_detection') == 'on':
        args.append('-sV')
    
    # Scan type specific arguments
    scan_type = form_data.get('scan_type')
    if scan_type == 'stealth':
        args.append('-sS')
    elif scan_type == 'aggressive':
        args.extend(['-A', '--version-all'])
    
    return ' '.join(args)

def get_port_range(form_data):
    scan_type = form_data.get('scan_type')
    if scan_type == 'quick':
        return '21-23,25,53,80,110,135,139,443,445,800,1433,3306,3389,5900,8080,8443'
    elif scan_type == 'astra':
        # Common Astra Cesbo ports
        # 80, 8080 - Main web interfaces
        # 554 - RTSP streaming
        # 5000, 8000-8081 - Alternative web/streaming ports
        return '80,554,5000,8000,8080,8081'
    elif scan_type == 'full':
        return '1-65535'
    elif scan_type == 'custom':
        return form_data.get('port_range', '1-65535')
    else:
        return '1-65535'

def scan_ip_range(ip_range, output_queue, scan_args, port_range):
   try:
      nm = nmap.PortScanner(nmap_search_path=('nmap', r'C:\Program Files (x86)\Nmap\nmap.exe'))
      for ip_str in ip_range:
         ip = str(ip_str)
         output_queue.put(f"Scanning IP: {ip}\n")
         output_queue.put(f"Port range: {port_range}\n")
         output_queue.put(f"Scan arguments: {scan_args}\n")
         
         # For full range scans, split into chunks
         if port_range == '1-65535':
             port_chunks = [(1,10000), (10001,20000), (20001,30000), (30001,40000), 
                          (40001,50000), (50001,60000), (60001,65535)]
             for start_port, end_port in port_chunks:
                 output_queue.put(f"Scanning ports {start_port}-{end_port}...\n")
                 nm.scan(hosts=ip, ports=f"{start_port}-{end_port}", arguments=scan_args)
                 process_scan_results(nm, ip, output_queue)
         else:
             nm.scan(hosts=ip, ports=port_range, arguments=scan_args)
             process_scan_results(nm, ip, output_queue)
             
   except Exception as e:
      output_queue.put(f"Error during scanning: {str(e)}\n")
      import traceback
      output_queue.put(f"Error details: {traceback.format_exc()}\n")
   finally:
     output_queue.put("Scan Complete\n")

def process_scan_results(nm, ip, output_queue):
    found_portals = []
    if ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            ports = nm[ip][proto].keys()
            for port in ports:
                try:
                    state = nm[ip][proto][port]['state']
                    if state == 'open':
                        service = nm[ip][proto][port]
                        output_queue.put(f"   Port {port}/{proto} is open\n")
                        output_queue.put(f"      Service: {service.get('name', 'unknown')}\n")
                        output_queue.put(f"      Version: {service.get('version', 'unknown')}\n")
                        output_queue.put(f"      Product: {service.get('product', 'unknown')}\n")
                        
                        try:
                            astra_check = is_astra_cesbo(ip, port)
                            if astra_check["found"]:
                                portal_info = {
                                    "ip": ip,
                                    "port": port,
                                    "url": astra_check["url"],
                                    "type": astra_check["type"],
                                    "title": astra_check["title"]
                                }
                                found_portals.append(portal_info)
                                
                                # Log to file
                                with open('astra_findings.txt', 'a') as f:
                                    f.write(f"IP: {ip}, Port: {port} - {astra_check['type']} - {astra_check['url']}\n")
                                
                                output_queue.put(f"      [FOUND] {astra_check['type']}\n")
                                output_queue.put(f"      [URL] {astra_check['url']}\n")
                        except Exception as e:
                            output_queue.put(f"      Error checking Astra: {str(e)}\n")
                except KeyError:
                    continue
    
    # If any portals were found, send them as a special message
    if found_portals:
        output_queue.put(f"FOUND_PORTALS:{json.dumps(found_portals)}\n")

def generate_scan_output(output_queue):
   while True:
         if not output_queue.empty():
             data = output_queue.get()
             if data:
                 yield f"data: {data}\n\n"
         else:
             time.sleep(0.1)

from queue import Queue
output_queue = Queue()
scan_thread = None

@app.route('/', methods=['GET', 'POST'])
def index():
     global scan_thread
     if request.method == 'POST':
         try:
             if scan_thread and scan_thread.is_alive():
                 return jsonify({"error": "A scan is already in progress."})

             ip_range = get_ip_range(request.form)
             if not ip_range:
                 return jsonify({"error": "No valid IP addresses to scan"})
                 
             scan_args = get_scan_arguments(request.form)
             port_range = get_port_range(request.form)

             output_queue.queue.clear()
             scan_thread = threading.Thread(
                 target=scan_ip_range, 
                 args=(ip_range, output_queue, scan_args, port_range)
             )
             scan_thread.daemon = True
             scan_thread.start()
             
             return jsonify({"success": True})

         except ValueError as e:
             return jsonify({"error": f"Invalid input: {str(e)}"})
         except Exception as e:
           return jsonify({"error": f"An error occurred: {str(e)}"})

     return render_template('index.html')

@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    global scan_thread
    try:
        if scan_thread and scan_thread.is_alive():
            # Signal the thread to stop
            output_queue.put("Scan stopped by user\n")
            scan_thread = None
            return jsonify({"success": True})
        return jsonify({"error": "No scan is currently running"})
    except Exception as e:
        return jsonify({"error": f"Error stopping scan: {str(e)}"})

@app.route('/stream')
def stream():
    return Response(generate_scan_output(output_queue), 
                   mimetype='text/event-stream',
                   headers={
                       'Cache-Control': 'no-cache',
                       'X-Accel-Buffering': 'no',
                       'Connection': 'keep-alive'
                   })

@app.route('/save_logs', methods=['POST'])
def save_logs():
    try:
        data = request.json
        log_content = data.get('logs', '')
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"scan_log_{timestamp}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(log_content)
            
        return jsonify({"success": True, "filename": filename})
    except Exception as e:
        return jsonify({"error": f"Error saving logs: {str(e)}"})

if __name__ == '__main__':
     app.run(debug=True, host="0.0.0.0")