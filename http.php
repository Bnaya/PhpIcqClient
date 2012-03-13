<?php
class http_client extends basic {

	var $sid;

	var $host;

	var $port;

	var $seq;

	var $curl;

	var $response;

	var $response_info;


	function http_client() {

		$this->curl = curl_init("");

		$this->seq = 1;


		if(defined('PROXY')) {

			curl_setopt($this->curl, CURLOPT_PROXY, PROXY_ADDR);
			curl_setopt($this->curl, CURLOPT_PROXYPORT, PROXY_PORT);
			curl_setopt($this->curl, CURLOPT_PROXYTYPE, 'CURLPROXY_HTTP');
			curl_setopt($this->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
		}

        curl_setopt($this->curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($this->curl, CURLOPT_TIMEOUT, 10);
		//curl_setopt($this->curl, CURLOPT_FRESH_CONNECT, true);

		//curl_setopt($this->curl, CURLOPT_BINARYTRANSFER, 1);
		curl_setopt($this->curl, CURLOPT_USERAGENT, '');
		curl_setopt($this->curl, CURLOPT_HEADER, false);
		//curl_setopt($this->curl, CURLOPT_HTTPHEADER, array('cache-control: no-store no-cache', 'pragma: no-cache', 'connection: keep-alive', 'accept:', 'content-type:', 'Proxy-Connection:', ));


	}

	function proxy_info() {

		curl_setopt($this->curl, CURLOPT_HTTPGET, true);

		curl_setopt($this->curl, CURLOPT_URL, "http://http.proxy.icq.com/hello");

	}

	function set_proxy_info($host, $port, $sid) {

		$this->host = $host;
		$this->port = $port;
		$this->sid = $sid;

	}


	function get(){

		curl_setopt($this->curl, CURLOPT_HTTPGET, true);
		curl_setopt($this->curl, CURLOPT_CUSTOMREQUEST, 'GET');

		curl_setopt($this->curl, CURLOPT_URL, "http://{$this->host}/monitor?sid={$this->sid}");

	}

	function post($body) {

		curl_setopt($this->curl, CURLOPT_CUSTOMREQUEST, 'POST');

		curl_setopt($this->curl, CURLOPT_URL, "http://{$this->host}/data?sid={$this->sid}&seq={$this->seq}");
		curl_setopt($this->curl, CURLOPT_POSTFIELDS, $body);

		$this->seq++;


	}

	function exec() {

		$this->response = curl_exec($this->curl);

		$this->response_info = curl_getinfo($this->curl);


		if($this->response_info['http_code'] != 200) {

			$this->error = $this->response_info['http_code'];
			return false;

		}


		return true;

	}

}


?>