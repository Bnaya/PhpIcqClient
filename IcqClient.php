<?php
/*
    GIT
*/
$path = pathinfo(__FILE__, PATHINFO_DIRNAME);
require("{$path}/basic.php");
require("{$path}/raw_reader.php");
require("{$path}/aim_http_packet.php");
require("{$path}/packet_reader.php");
require("{$path}/packet_builder.php");
require("{$path}/http.php");
require("{$path}/httpphp2icq.php");

class IcqClient extends basic {

	/**
	 * Enter description here...
	 *
	 * @var php2icq
	 */
	public $httphp2icq, $uin, $password, $last_activity;


	public function ready($uin, $password) {

		$this->uin = $uin;
		$this->password = $password;

		$res = sql_query(
		sprintf("SELECT * FROM `sessions` WHERE `uin`=%d AND `password`='%s' LIMIT 1", $uin, mysql_real_escape_string($password))
		);

		if(mysql_num_rows($res) == 1) {

			$uin = mysql_fetch_assoc($res);
			mysql_free_result($res);

			if($uin['last_activity'] > (time() - 96)) {
				$this->httphp2icq = unserialize($uin['obj']);
				//var_export(unserialize($uin['obj']));

				if($this->httphp2icq->load_session()) {
					return true;
				}


			}
		}




		$this->httphp2icq = new httphp2icq($this->uin, $password, STATUS_INVISIBLE);
		
		
		$this->httphp2icq->get_proxy_info();

		if(!$this->httphp2icq->login()) {

			$this->add_error($this->httphp2icq->get_errors());

			return false;
		}

		return true;

	}

	public function check_login() {

	}

	public function send_sms($number, $text) {

		$number = preg_replace("#[^0-9]#", '', $number);
		
		if(preg_match("#^0[0-9]{9}$#", $number) == 0) {


			$this->save_session();
			$this->add_error("מספר פלאפון לא תקין:" . $number);

			return false;
		}

		$number = '972' . substr($number, 1);

		if(!$this->httphp2icq->send_sms($number, $text)) {


			$this->save_session();
			$this->add_error($this->httphp2icq->get_errors());

			return false;
		}

		$this->save_session();
		
		sql_query(
		sprintf("INSERT INTO `sms_log` (`uin`,`server`,`ip`) VALUES ('%s','%s','%s')", $this->uin, mysql_real_escape_string($_SERVER['HTTP_HOST']), $_SERVER['REMOTE_ADDR'])
		);
		
		return true;

	}

	public function save_session() {
		sql_query("REPLACE `sessions` SET `last_activity`=" . time() .",`obj`='" . mysql_real_escape_string(serialize($this->httphp2icq)) . "',`uin` = {$this->uin},`password`='{$this->password}'");
	}

}
?>