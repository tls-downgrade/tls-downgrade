

#### Setup

1. Setup the mitmproxy according to their official [website](https://github.com/mitmproxy/mitmproxy/blob/main/CONTRIBUTING.md).

2. Modify the mitmproxy with the below command
   
   ```
   git clone https://github.com/tls-downgrade/tls-downgrade.git
   cp proxy.py client_hello.py downgrade_poc.py ./mitmproxy
   cp next_layer.py ./mitmproxy/addons/
   ```

3. Run the mitmproxy with the following command:
   
   ```
   mitmproxy -s downgrade_poc.py
   ```


