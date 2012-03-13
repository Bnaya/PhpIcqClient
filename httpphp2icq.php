<?php
//******************************************************
// Some defines used for describing the FLAP-Channel
//******************************************************
define('FLAP_CHANNEL_NEW_CONNECTION_NEGOTIATION'                , 0x01);
define('FLAP_CHANNEL_SNAC_DATA'                                                        , 0x02);
define('FLAP_CHANNEL_LEVEL_ERROR'                                                , 0x03);
define('FLAP_CHANNEL_CLOSE_CONNECTION_NEGOTIATION'                , 0x04);
define('FLAP_CHANNEL_KEEP_ALIVE'                                                , 0x05);

$flaps = array();
$flaps[0x01] = "FLAP CHANNEL NEW CONNECTION NEGOTIATION";
$flaps[0x02] = "FLAP CHANNEL SNAC DATA";
$flaps[0x03] = "FLAP CHANNEL LEVEL ERROR";
$flaps[0x04] = "FLAP CHANNEL CLOSE CONNECTION NEGOTIATION";
$flaps[0x05] = "FLAP CHANNEL KEEP ALIVE";

//******************************************************
// Online Status defines
//******************************************************
define('STATUS_WEBAWARE',        0x0001);        // Status webaware flag
define('STATUS_SHOWIP',                0x0002);        // Status show ip flag
define('STATUS_BIRTHDAY',        0x0008);        // User birthday flag
define('STATUS_WEBFRONT',        0x0020);        // User active webfront flag
define('STATUS_DCDISABLED', 0x0100);        // Direct connection not supported
define('STATUS_DCAUTH',                0x1000);        // Direct connection upon authorization
define('STATUS_DCCONT',                0x2000);        // DC only with contact users


define('STATUS_ONLINE',                0x0000);        // Status is online
define('STATUS_AWAY',                0x0001);        // Status is away
define('STATUS_DND',                0x0002);        // Status is no not disturb (DND);
define('STATUS_NA',                        0x0004);        // Status is not available (N/A);
define('STATUS_OCCUPIED',        0x0010);        // Status is occupied (BISY);
define('STATUS_FREE4CHAT',        0x0020);        // Status is free for chat
define('STATUS_INVISIBLE',        0x0100);        // Status is invisible



/**
 * The main class
 *
 * It contains all the functions to communicate with
 * the icq server.
 *
 * @package classlib
 */
class httphp2icq extends raw_reader
{



	var $debug_funcs = array();


	/**
	 * Icq Uin/Account
	 *
	 * The icq username/number/email to connect.
	 *
	 * @access private
	 * @var string
	 */
	var $uin;

	/**
	 * Account password
	 *
	 * This is the password used to login into the mentioned account.
	 *
	 * @access private
	 * @var string
	 */
	var $pass;

	/**
	 * Current connection handel
	 *
	 * All functions use this socket handle to send/read
	 * the server data.
	 *
	 * @access private
	 * @var int
	 */
	var $conn;

	/**
	 * FLAP sequence id
	 *
	 * This var contains the current sequence id. The sequence
	 * id sits in the FLAP header and get incremented by every send
	 * procedure. This is done in {@link php2icq::add_flap_header()}.
	 *
	 * @access private
	 * @var int
	 */
	var $sequence_id;

	/**
	 * Errorstring
	 *
	 * If a function failed (only the public functions),
	 * then the errorstring get filled with a usefull errormessage.
	 * The user may call {@link php2icq::get_error()} to get
	 * the error message.
	 *
	 * @access private
	 * @var string
	 */
	var $errors = array();

	var $error;


	var $debug;

	/**
	 * Loginerror allocation
	 *
	 * When we send the auth packet, the server may send
	 * an error packet. There are several possibilities what is happended then.
	 *
	 * @access private
	 * @var array
	 */
	var $login_errno_arr;

	/**
	 * Supportet SNAC families
	 *
	 * Contains the SNAC families supportet by the server.
	 * The associated versions are stored in annother array.
	 *
	 * @access private
	 * @var array
	 * @see php2icq::$snac_versions
	 */
	var $snac_families;

	/**
	 * Supportet SNAC versions
	 *
	 * Contains the versions of the SNAC families supportet by the server.
	 * The associated familie names are stored in annother array.
	 *
	 * @access private
	 * @var array
	 * @see php2icq::$snac_families
	 */
	var $snac_versions;

	/**
	 * The used uin online status
	 *
	 * You can choose your status from the following list (only one):<br />
	 * STATUS_ONLINE<br />
	 * STATUS_AWAY<br />
	 * STATUS_DND<br />
	 * STATUS_NA<br />
	 * STATUS_OCCUPIED<br />
	 * STATUS_FREE4CHAT<br />
	 * STATUS_INVISIBLE<br />
	 *
	 * @access private
	 * @var int
	 */
	var $online_status;


	var $login_errno;



	var $packet_reader;

	var $proxy_ip;

	var $proxy_port;

	var $sid;

	var $post_seq;
	
	/*
	That var is for the ath the uin with a phone number
	*/
	var $DC_auth_cookie;	

	/**
	 * Enter description here...
	 *
	 * @var http_client
	 */
	var $http_client;

	var $cons = 0;

	var $in_packets = array();
	var $income_packets_pointer = 0;

	
	private function add_in_packet($packets) {
		foreach ($packets as $p) {
			$this->in_packets[] = $p;
		}
	}

	/**
	 * Enter description here...
	 * @return bool
	 */
	function load_session() {

		$p = $this->http_client->seq;
		
		$this->http_client = new http_client();
		$this->http_client->set_proxy_info($this->proxy_ip, $this->proxy_port, $this->sid);
		$this->http_client->seq = $p;
		
		if(!$this->fsend($this->cons, 0x0005, $this->add_flap_header('', 0x0005))) {
			return false;	
		}
		
		return true;

	}

	function get_proxy_info() {


		$this->http_client->proxy_info();

		$this->http_client->exec();
		$response = $this->http_client->response;

		$packetReader = new packet_reader($response);

		$packet_length = $packetReader->fget_word();

		$protocol_type = $packetReader->fget_word();

		$packet_type = $packetReader->fget_word();

		//6 unkonown bytes

		$packetReader->fget_string(6);
		$a1 = 5;
		//read the sid

		$this->sid = $packetReader->fget_hex_string(16);

		//proxy server ip length unknowon bytes

		$ip_len = $packetReader->fget_word(2);

		//get the http icq server ip and port

		$this->proxy_ip = $packetReader->fget_string($ip_len);

		$this->proxy_port = $packetReader->fget_word();

		$this->http_client->set_proxy_info($this->proxy_ip, $this->proxy_port, $this->sid);

		//$this->monitor = new monitor($this->proxy_ip, $this->proxy_port, $this->sid);

		//$this->http = new http($this->proxy_ip, $this->proxy_port, $this->sid);
		return true;

	}



	//###########################################################################################################################################
	//
	// Private Methods (should not be called from outside of the class)
	//
	//###########################################################################################################################################
	/**
	 * Creates error strings for the exspected login errors.
	 *
	 * If the authentication fails the server sends an error
	 * TLV containing one of these error codes. This array
	 * is later used to identify the error codes and give the user
	 * some usefull information.
	 *
	 * @access private
	 * @see php2icq::login()
	 */
	function create_login_errno_arr()
	{
		$this->login_errno_arr[0x0001] = 'Invalid nick or password';
		$this->login_errno_arr[0x0002] = 'Service temporarily unavailable';
		$this->login_errno_arr[0x0003] = 'All other errors';
		$this->login_errno_arr[0x0004] = 'Incorrect nick or password, re-enter';
		$this->login_errno_arr[0x0005] = 'Mismatch nick or password, re-enter';
		$this->login_errno_arr[0x0006] = 'Internal client error (bad input to authorizer)';
		$this->login_errno_arr[0x0007] = 'Invalid account';
		$this->login_errno_arr[0x0008] = 'Deleted account';
		$this->login_errno_arr[0x0009] = 'Expired account';
		$this->login_errno_arr[0x000A] = 'No access to database';
		$this->login_errno_arr[0x000B] = 'No access to resolver';
		$this->login_errno_arr[0x000C] = 'Invalid database fields';
		$this->login_errno_arr[0x000D] = 'Bad database status';
		$this->login_errno_arr[0x000E] = 'Bad resolver status';
		$this->login_errno_arr[0x000F] = 'Internal error';
		$this->login_errno_arr[0x0010] = 'Service temporarily offline';
		$this->login_errno_arr[0x0011] = 'Suspended account';
		$this->login_errno_arr[0x0012] = 'DB send error';
		$this->login_errno_arr[0x0013] = 'DB link error';
		$this->login_errno_arr[0x0014] = 'Reservation map error';
		$this->login_errno_arr[0x0015] = 'Reservation link error';
		$this->login_errno_arr[0x0016] = 'The users num connected from this IP has reached the maximum';
		$this->login_errno_arr[0x0017] = 'The users num connected from this IP has reached the maximum (reservation)';
		$this->login_errno_arr[0x0018] = 'Rate limit exceeded (reservation). Please try to reconnect in a few minutes';
		$this->login_errno_arr[0x0019] = 'User too heavily warned';
		$this->login_errno_arr[0x001A] = 'Reservation timeout';
		$this->login_errno_arr[0x001B] = 'You are using an older version of ICQ. Upgrade required';
		$this->login_errno_arr[0x001C] = 'You are using an older version of ICQ. Upgrade recommended';
		$this->login_errno_arr[0x001D] = 'Rate limit exceeded. Please try to reconnect in a few minutes';
		$this->login_errno_arr[0x001E] = 'Can\'t register on the ICQ network. Reconnect in a few minutes';
		$this->login_errno_arr[0x0020] = 'Invalid SecurID';
		$this->login_errno_arr[0x0022] = 'Account suspended because of your age (age < 13)';
		$this->login_errno_arr[0xFFFF] = 'Wrong errornumber format';
	}


	/**
	 * Opens socket-connection to specified server.
	 *
	 * The Connection handler will be stored to a class var. The method
	 * only return true or false (success or failure). The FLAP sequence id, which
	 * is incremented for every send process get reseted.
	 *
	 * @param string The ip or url to connect to
	 * @param int The port to connect to
	 * @return bool True if successfully. False if connection failed (e.g. due timeout).
	 * @access private
	 * @see php2icq::$con
	 * @see php2icq::close_connection()
	 */
	function open_connection($addr, $port)
	{

		$this->cons ++;
		$pb = new packet_builder(0x0003, $this->cons);
		$pb->add_word(strlen($addr));
		$pb->add_string($addr);
		$pb->add_word($port);
		$this->add_in_packet(array($pb));
		$this->http_client->post($pb->get_packet());

		if(!$this->http_client->exec()) {

			$this->add_error('error posting:' . $this->http_client->get_errors());
			return false;

		}

		$this->fget();

		/*if($this->packet_reader->packets[0]->type != 0x0004) {

		$this->add_error('the packet is in wrong type');
		return false;

		}*/


		return true;
	}


	/**
	 * Closes connection using current server handle.
	 *
	 * Nothing else than fclose(). Please use this function to close the connection.
	 *
	 * @return bool True if successfully. False if connection handle is invalid.
	 * @access private
	 * @see php2icq::$con
	 * @see php2icq::open_connection()
	 */
	function close_connection($con = 0x0001) {

		$this->fsend($con, 0x0006);

		$this->fget();

		return true;
	}

	/**
	 * Writes data to the current TCP stream.
	 *
	 * Nothing else than fwrite(). Please use this function to write.
	 *
	 * @param mixed The data which will be send.
	 * @access private
	 */
	function fsend($connection, $packet_type = 0x0005, $data = '')
	{


		$pb = new packet_builder($packet_type, $connection);

		if($data) {
			$pb->add_string($data);
		}
		/* */

		$packet = $pb->get_packet();
		$this->add_in_packet(array($pb));
		$this->http_client->post($packet);
		if(!$this->http_client->exec()) {

			$this->add_error('error posting packet');
			return false;
		}

		return true;

	}

	/**
	 * Enter description here...
	 *
	 * @param int $type
	 * @return bool
	 */
	function fget($type = 0x0005) {


		$this->http_client->get();

		if(!$this->http_client->exec()) {

			$this->add_error("error getting packet", 0);
			return false;
		}

		$packet = $this->http_client->response;


		$this->packet_reader = '';
		$this->packet_reader = new packet_reader($packet);

		$this->packet_reader->analyze();
		$this->add_in_packet($this->packet_reader->packets);

		return true;

	}


	/**
	 * Splits a number into chosen byte count.
	 *
	 * Splits a number into the count of the
	 * chosen bytes and save it to a string.
	 * This function is mainly used to fit the protocoll.
	 *
	 * @param int The number to split
	 * @param int The resulting byte count (In how many pieces the number get splitted)
	 * @return mixed If the method was successfully it returns a string with the splitted number-bytes.
	 * False if the number is to high for the chosen byte count.
	 * @access private
	 */
	function split_byte($number, $bytes)
	{
		// If the number cannot be displayed with the chosen byte count
		if ($number >= pow(0x100, $bytes))
		{
			return false;
		}

		$splitted_bytes = '';        // the number will be saved as a string (for sending)

		for ($i = 1; $i <= $bytes; $i++)
		{
			// Zuerst bestimmen wir den Divisor f?r die aktuelle Stelle der Zahl
			$power = pow(0x100, $bytes - $i);

			$full = (int) ($number / $power);
			$splitted_bytes .= chr($full);

			// Den Rest nehmen wir als neuen Hex-Wert f?r die n�chste Schleife
			$number = $number - ($full * $power);
		}
		return $splitted_bytes;
	}


	/**
	 * Adds the FLAP header to a packet body.
	 *
	 * The method is very usefull, because you only have to care about
	 * the body of a packet. If you have SNAC data in your packet call
	 * {@link php2icq::add_snac_header()}. <--- This method will add
	 * the FLAP header, too (and SNAC of course ;)). This method also increments the FLAP sequence id.
	 *
	 *
	 * @param string The packet body
	 * @param int The FLAP channel which will be used
	 * @return string A complettly sending reading string
	 * @access private
	 * @see php2icq::add_snac_header(), php2icq::make_tlv()
	 */
	function add_flap_header($flap_body, $channel)
	{
		//flap header
		$flap =
		chr(0x2A).                                                                        //FLAP id byte
		chr($channel).                                                                //FLAP channel
		$this->split_byte($this->sequence_id, 2).        //FLAP datagram seq number
		$this->split_byte(strlen($flap_body), 2).        //FLAP data size
		$flap_body                                                                        //FLAP data
		;

		// For every send-process the sequence id has to be incremented
		$this->sequence_id++;

		return $flap;
	}


	/**
	 * Adds the SNAC & FLAP header to a packet body.
	 *
	 * The method is very usefull, because you only have to care about
	 * the body of a packet. It will first add SNAC header and then
	 * {@link php2icq::add_flap_header()}. If you have only FLAP data (without a SNAC)
	 * just call {@link php2icq::add_flap_header()}.
	 *
	 *
	 * @param string The packet body
	 * @param int The SNAC family
	 * @param int The SNAC sub-family
	 * @param int The SNAC request id (currently not in use, set it to 0)
	 * @param int The SNAC flags
	 * @return string A completly sending reading string
	 * @access private
	 * @see php2icq::add_flap_header(), php2icq::make_tlv()
	 */
	function add_snac_header($snac_body, $snac_fam, $snac_sub, $snac_request_id, $snac_flags = 0x0000)
	{
		$snac =
		$this->split_byte($snac_fam, 2).                //Family (service) id number
		$this->split_byte($snac_sub, 2).                //Family subtype id number
		$this->split_byte($snac_flags, 2).                //SNAC flags
		$this->split_byte($snac_request_id, 4).        //SNAC request id
		$snac_body;                                                                //SNAC data
		;

		$packet =
		$this->add_flap_header($snac, 0x02)                //FLAP Header
		;

		return $packet;
	}

	/**
	 * Makes a TLV from the given parameters
	 *
	 * You only have to enter the 2 parameters and you get
	 * one TLV string easy to use. Simply add it to your current
	 * packet body.
	 *
	 *
	 * @param int The TLV identifier
	 * @param string The content of the TLV (uin, password, email, search strings...)
	 * @param int Is the TLV content a defined count of bytes? If true enter the byte count here. If its a string enter 0.
	 * @return string The merged TLV
	 * @access private
	 * @see php2icq::add_flap_header(), php2icq::add_snac_header()
	 */
	function make_tlv($tlv_id, $tlv_data, $tlv_bytes)
	{
		// if tlv data is a number
		if ($tlv_bytes > 1)
		{
			$tlv_data = $this->split_byte($tlv_data, $tlv_bytes);
		}

		// a tlv
		$tlv =
		$this->split_byte($tlv_id, 2).                                //TLV id word
		$this->split_byte(strlen($tlv_data), 2).        //TLV data length
		$tlv_data                                                                        //TLV data
		;

		return $tlv;
	}


	/**
	 * Encodes the password.
	 *
	 * Takes the clear password string and encodes it with
	 * the given array.
	 * The icq server only accepts the encoded password.
	 *
	 * @param string The clear password to encode
	 * @return string The encoded password string
	 * @access private
	 */
	function roast_password($pw)
	{
		$roast = array(0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92, 0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C);

		$roastet_password = '';

		for ($i = 0; $i < strlen($pw); $i++)
		{
			$roastet_password .= @chr($roast[$i] ^ @ord(substr($pw, $i, 1)));
		}

		return $roastet_password;
	}


	/**
	 * Reads the FLAP header an check it for validity
	 *
	 * You don't have to care about the FLAP header anymore. When you read
	 * a packet just call this function first.
	 *
	 * @param int The exspected FLAP header
	 * @return mixed Length of the FLAP body as int or false if failed
	 * @access private
	 * @see php2icq::fget_byte(), php2icq::fget_word(), php2icq::fget_dword(), php2icq::fget_string(), php2icq::fget_dummy_bytes(), php2icq::fget_dummy_packet()
	 */
	function check_flap_header($flap_channel)
	{
		// Proof flap-id
		if (($byte=$this->fget_byte() != 0x2a))
		{

			$this->error = "Unexpected FLAP packet start-byte({$byte})";
			$this->add_error($this->error, 0);
			if(isset($this->debug_funcs['check_flap_header'])) {

				call_user_func($this->debug_funcs['check_flap_header'], debug_backtrace());
			}

			$this->close_connection();
			return false;
		}
		// Channel must be the chosen one
		if ($byte=$this->fget_byte() != $flap_channel)
		{
			$this->error = "Unexpected FLAP packet channel({$byte})";
			$this->add_error($this->error, 0);

			$this->close_connection();
			return false;
		}
		// Overread Seq.-No
		$this->fget_dummy_bytes(2);
		// Read the length of the FLAP packet
		$flap_length = $this->fget_word();

		return $flap_length;
	}

	/**
	 * Reads the SNAC header an check it for validity and returns some info about the SNAC
	 *
	 * You don't have to care about the SNAC header anymore. When you read
	 * a packet just call this function first. It will return all information need
	 * about the SNAC packet.
	 *
	 * @param int The exspected SNAC-Family
	 * @param int The exspected SNAC-Sub-Family
	 * @return mixed Length of the FLAP body as int or false if failed
	 * <br />The returned array contains:
	 * <br />
	 * [0] = SNAC flags <br />
	 * [1] = SNAC request id
	 * @access private
	 * @see php2icq::fget_byte(), php2icq::fget_word(), php2icq::fget_dword(), php2icq::fget_string(), php2icq::fget_dummy_bytes(), php2icq::fget_dummy_packet(),
	 * php2icq::check_flap_header()
	 */
	function check_snac_header($snac_fam, $snac_sub)
	{
		// the returned info array
		$snac_info = array();

		// Proof SNAC fam
		if ($byte = $this->fget_word() != $snac_fam)
		{
			$this->error = 'Unexpected SNAC Family({$byte})';
			$this->add_error("Unexpected SNAC Family({$byte}", 0);
			$this->close_connection();
			return false;
		}
		// Proof SNAC sub-fam
		if ($byte = $this->fget_word() != $snac_sub)
		{
			$this->error = 'Unexpected SNAC Sub-Family({$byte})';
			$this->add_error("Unexpected SNAC Sub-Family({$byte}", 0);
			$this->close_connection();
			return false;
		}
		// read flags
		$snac_info[0] = $this->fget_word();
		// read request idea
		$snac_info[1] = $this->fget_dword();

		return $snac_info;
	}

	
	function read_snac_header()
	{
		// the returned info array
		$snac_info = array();

		// Proof SNAC fam
		$snac_info['fam'] = $this->fget_word();

		// Proof SNAC sub-fam
		$snac_info['sub'] = $this->fget_word();
		

		// read flags
		$snac_info['flags'] = $this->fget_word();
		// read request idea
		$snac_info['id'] = $this->fget_dword();

		return $snac_info;
	}		
	
	/**
	 * convert the hebrew chars in the sms message to
	 * By me
	 * @param string The sms message text
	 */
	function Heb_dict( $str )
	{
		for($i = 1; $i<= 28;$i++)
		{
			$str = str_replace(chr($i + 223), $this->Hex2Str("d7" . DecHex($i + 143)),$str);
		}
		return $str;
	}

	/**
	 * Not documented yet
	 * By me
	 * @param string Hex data to convert to string
	 */
	function Hex2Str( $Hex )
	{
		$OneHex="";
		$k=0;

		if(strlen($Hex) == 2)
		{
			return pack("H*",$Hex);
		}
		else
		{
			for($k = 0; $k<strLen($Hex); $k=$k+2)
			{
				$OneHex .= pack( "H*" , $Hex[$k] . $Hex[$k+1] );
			}
			return $OneHex;
		}
	}

	/*
	*
	* By me
	*/
	function revhex( $daf, $laf ) {
		$j = 0;
		$adf="";

		if(strlen($daf) < $laf) {
			$adf = "";
			for($i = 1; $i<=$laf - strlen($daf); $i++)
			$adf = "0" . $adf;
			$daf = $adf . $daf;
		}
		$revhex = "";
		$j = (int)floor(strlen($daf) / 2);
		for($i = 1; $i<=(int)floor(strlen($daf) / 2); $i++)
		{
			$revhex = $revhex . substr($daf, ($j * 2) -2, 2);
			$j--;
		}
		return $revhex;
	}

	/**
	 * By my
	 *
	 *
	 *
	 */
	function Str2Hex( $str )
	{
		$ch="";
		$Str2Hex='';
		for($i = 0; $i< strlen($str); $i++)
		{
			$ch = dechex(ord(substr($str, $i, 1)));
			if(strlen($ch) == 1)
			$ch = "0" . $ch;
			$Str2Hex = $Str2Hex . $ch;
		}
		return $Str2Hex;
	}

	//###########################################################################################################################################
	//
	// Public Methods (this methods can be uses from the otside of the class)
	//
	//###########################################################################################################################################
	/**
	 * The Constructor
	 *
	 * It does some simple construction tasks.
	 *
	 * @param string The username/icqnumber to login.
	 * @param string The password used to login.
	 * @param int The status the used uin will have when you login. These are the available staus commands:
	 * STATUS_ONLINE<br />
	 * STATUS_AWAY<br />
	 * STATUS_DND<br />
	 * STATUS_NA<br />
	 * STATUS_OCCUPIED<br />
	 * STATUS_FREE4CHAT<br />
	 * STATUS_INVISIBLE<br />
	 * @access public
	 */
	function httphp2icq($uin, $pass, $online_status)
	{
		$this->uin = $uin;
		$this->pass = $pass;
		$this->online_status = $online_status;
		$this->sequence_id = 14628;
		$this->post_seq = 1;
		
		
		
		$this->http_client = new http_client();
			
		$this->errors = array();
		
		$this->create_login_errno_arr();

	}


	/**
	 * Authentication & Login to the main server
	 *
	 * It uses the stored uin & password to pass the authentication.
	 * After that it connects to the icq main server and prepare
	 * the connection for further use. If an error occured you may
	 * use {@link php2icq::get_error()} to get information about the error.
	 *
	 * @return bool True if success. False if an error occured.
	 * @access public
	 */
	function login()
	{

		//####################################################################
		//
		// Login stage I: Channel 0x01 authorization
		//
		//####################################################################
		//******************************************************
		//  Connect to the authserver
		//******************************************************
		//if (!$this->open_connection('login.icq.com', 5190))
		if (!$this->open_connection('login.icq.com', 443))
		//   if (!$this->open_connection('64.12.200.89', 5190))
		{
			return false;
		}


		//******************************************************
		// Send: CLI_IDENT
		//******************************************************
		// Client properties
		$client_name = 'ICQBasic';  // Plz do not change. Its usefull to spread php2icq.
		$client_id = 226;
		$client_major_version = 20;
		$client_minor_version = 52;
		$client_lesser_version = 0x0002;
		$client_build_version = 9000;
		$client_distribution_number = 1083;
		$client_language = 'en';  // you can change this
		$client_country = 'us';   // you can change this

		// flap body
		$auth =
		$this->split_byte(0x00000001, 4).                                                                //protocol version number
		$this->make_tlv(0x0001, $this->uin, 0).                                                        //screen name (uin)
		$this->make_tlv(0x0002, $this->roast_password($this->pass), 0).        //roasted password
		$this->make_tlv(0x0003, $client_name, 0).                                                //client id string
		$this->make_tlv(0x0016, $client_id, 2).                                                        //client id
		$this->make_tlv(0x0017, $client_major_version, 2).                                //client major version
		$this->make_tlv(0x0018, $client_minor_version, 2).                                //client minor version
		$this->make_tlv(0x0019, $client_lesser_version, 2).                                //client lesser version
		$this->make_tlv(0x001A, $client_build_version, 2).                                //client build number
		$this->make_tlv(0x0014, $client_distribution_number, 4).                //distribution number
		$this->make_tlv(0x000F, $client_language, 0).                                        //client language (2 symbols)
		$this->make_tlv(0x000E, $client_country, 0)                                                //client country (2 symbols)
		;



		$this->fsend(0x01,0x0005, $this->add_flap_header($auth, 0x01));

		$this->fget();
		
		//check aim_http_packet channel for the right channel
		
		if($this->packet_reader->packets[0]->type != 0x0005) {
			
			//file_put_contents("c:/log/p" . time(), print_r($this->in_packets, 1));
			$this->add_error(
				"http packet in bad type " . dechex($this->packet_reader->packets[0]->type) .
			' we have:(' . count($this->packet_reader->packets) . ') packets total'
			, 0);
			return false;
		}
		
		$this->set_readFrom($this->packet_reader->packets[0]->data);

	
		//******************************************************
		// Overread: standart ACK packet
		//******************************************************
		/*if (!$this->fget_dummy_packet(FLAP_CHANNEL_NEW_CONNECTION_NEGOTIATION))
		{
		return false;
		}*/


		//******************************************************
		// Read: SRV_COOKIE
		//******************************************************
		// Check FLAP Header
		
		if (!($flap_length = $this->check_flap_header(FLAP_CHANNEL_CLOSE_CONNECTION_NEGOTIATION)))
		{
			//var_dump($this->packet_reader->packets);
			return false;
		}
		// Read all TLV's
		while ($flap_length > 0)
		{
			// Read TLV id
			$Value_id = $this->fget_word();
			// Read length of the TLV value
			$Value_length = $this->fget_word();
			// We are just looking for some special TLV's
			if ($Value_id == 0x0005) // BOS Server ID
			{
				$BOS_server_ip = $this->fget_string($Value_length);
			}
			elseif ($Value_id == 0x0006) // Authorisation Cookie
			{
				$Auth_cookie = $this->fget_string($Value_length);
			}
			elseif ($Value_id == 0x0008) // Login Error
			{
				//******************************
				// login error occurred
				//******************************
				if ($Value_length == 2) // error number should be 2 bytes
				{
					$login_errno = $this->fget_word(); // get error number from tlv
					$this->login_errno = $login_errno;
				}
				else
				{
					$login_errno = 0xFFFF;        // set it to unknown error format if the errno is not 2 bytes
				}
				if (isset($this->login_errno_arr[$login_errno]))        // check if it is a known error
				{
					$login_error_string = $this->login_errno_arr[$login_errno];
				}
				else
				{
					$login_error_string = 'Unknown Error';
				}
				$this->error = 'Login failed.'.$login_error_string.'.';
				$this->add_error('Login failed.'.$login_error_string.'.');
				$this->close_connection();
				return false;
			}
			else
			{
				// Overread the other crap
				$this->fget_dummy_bytes($Value_length);
			}
			$flap_length -= (4 + $Value_length);
		}


		// Disconnect form Auth Server
		$this->close_connection();


		//####################################################################
		//
		// Login stage II: Protocol negotiation
		//
		//####################################################################


		//******************************
		// connect to BOS server
		//******************************
		// Seperate ip from port number
		$BOS_array = explode(':', $BOS_server_ip);
		//Initiate Connection to BOS Server

		if (!$this->open_connection($BOS_array[0], $BOS_array[1]))
		{
			return false;
		}


		//******************************
		// Send: CLI_COOKIE
		//******************************
		//flap data
		$auth_cookie =
		$this->split_byte(0x01, 4).                                                                                                                                        //protocol version number
		$this->split_byte(0x06, 2).$this->split_byte(strlen($Auth_cookie), 2).$Auth_cookie                        //Auth Cookie
		;

		$this->fsend($this->cons, 0x0005, $this->add_flap_header($auth_cookie, 0x01));
		$this->fget();

		//******************************************************
		// Overread: ACK packet
		/*//******************************************************
		if (!$this->fget_dummy_packet(FLAP_CHANNEL_NEW_CONNECTION_NEGOTIATION))
		{
		return false;
		}*/


		//******************************************************
		// Overread: SNAC(01,03)  SRV_FAMILIES
		//******************************************************
		/*if (!$this->fget_dummy_packet(FLAP_CHANNEL_SNAC_DATA))
		{
		return false;
		}*/


		//******************************************************
		// Send: SNAC(01,17)  CLI_FAMILIES_VERSIONS
		// we send the families incl. versions which are
		// supported/used by this lib
		// see SNAC(01,02)
		//******************************************************
		//snac data
		$snac_body = $this->split_byte(0x0001, 2).$this->split_byte(0x0004, 2).                // Generic service controls v4
		$this->split_byte(0x0004, 2).$this->split_byte(0x0001, 2)                                        // ICBM (messages) service  v1
		;

		$this->fsend($this->cons, 0x0005,$this->add_snac_header($snac_body, 0x0001, 0x0017, 0));

		$this->fget();

		$this->set_readFrom($this->packet_reader->packets[0]->data);

		//******************************************************
		// Read: SNAC(01,18)  SRV_FAMILIES_VERSIONS
		//******************************************************
		// Check FLAP Header
		if (!($flap_length = $this->check_flap_header(FLAP_CHANNEL_SNAC_DATA)))
		{
			return false;
		}
		// Check FLAP Header
		if (!($this->check_snac_header(0x0001, 0x0018)))
		{
			return false;
		}
		// Read all supported families
		$flap_length -= 10;
		while ($flap_length > 0)
		{
			//$this->snac_families[] = $this->fget_word($BOS);
			//$this->snac_versions[] = $this->fget_word($BOS);
			$this->snac_families[] = $this->fget_word();
			$this->snac_versions[] = $this->fget_word();
			$flap_length -= 4;
		}


		//******************************************************
		// Send: SNAC(01,06)  CLI_RATES_REQUEST
		//******************************************************
		$snac_body = '';
		$this->fsend($this->cons, 0x0005, $this->add_snac_header($snac_body, 0x0001, 0x0006, 0));

		$this->fget();

		//	$this->packet_reader->packets[0]->data .= $this->packet_reader->packets[1]->data;

		$this->set_readFrom($this->packet_reader->packets[0]->data);

		//******************************************************
		// Read: SNAC(01,07)  SRV_RATE_LIMIT_INFO
		// --------
		// we do not need this information, yet
		// this will be implemented later
		//******************************************************
		// Check FLAP Header
		if (!($flap_length = $this->check_flap_header(FLAP_CHANNEL_SNAC_DATA)))
		{
			return false;
		}
		// Check FLAP Header
		if (!($this->check_snac_header(0x0001, 0x0007)))
		{
			return false;
		}
		// Read number of rate classes
		$rate_classes = $this->fget_word();
		// Overread the rest
		$this->fget_dummy_bytes($flap_length - 12);


		//******************************************************
		// Send: SNAC(01,08)  CLI_RATES_ACK
		//******************************************************
		$snac_body = '';
		for ($i = 1; $i <= $rate_classes; $i++)
		{
			$snac_body .= $this->split_byte($i, 2);
		}

		$this->fsend($this->cons, 0x0005, $this->add_snac_header($snac_body, 0x0001, 0x0008, 0));
		//$this->fget();

		//####################################################################
		//
		// Login stage III: Services setup
		//
		//####################################################################

		// Skipped




		//####################################################################
		//
		// Login stage IV: Final actions
		//
		//####################################################################
		//******************************************************
		// Send: SNAC(01,1E)  CLI_SETxSTATUS
		//******************************************************
		
		$this->DC_auth_cookie = rand(0, 1073741824);
		
		$DC_INFO = $this->split_byte(0, 4) . // DC Internal ip address
		$this->split_byte(0,4). //DC tcp port
		$this->split_byte(0x04, 1) . //DC type
		$this->split_byte(0x0009, 2) . //DC protocol version 
		$this->split_byte($this->DC_auth_cookie, 4) .  	//DC auth cookie
		$this->split_byte(0x00000003, 4) . //Client futures
		/*
 xx xx xx xx  	   	dword  	   	last info update time
 xx xx xx xx 	  	dword 	  	last ext info update time (i.e. icqphone status)
 xx xx xx xx 	  	dword 	  	last ext status update time (i.e. phonebook)
 xx xx 	  	word 	  	unknown
		*/
		$this->split_byte(0, 14);

		
		$snac_body =
		$this->make_tlv(0x0006, $this->split_byte(STATUS_DCDISABLED | STATUS_WEBAWARE, 2).$this->split_byte($this->online_status, 2), 0)        // TLV.Type(0x06) - user status / status flags
		.
		$this->make_tlv(0x000C, $DC_INFO, 0)
		;

		$this->fsend($this->cons, 0x0005, $this->add_snac_header($snac_body, 0x0001, 0x001E, 0));

		$this->fget();


		$this->set_readFrom($this->packet_reader->packets[0]->data);;
		//******************************************************
		// Overread: SNAC(01,0F)  Requested online info response
		//******************************************************
		if (!$this->fget_dummy_packet(FLAP_CHANNEL_SNAC_DATA))
		{
			return false;
		}

		//******************************************************
		// Send: SNAC(01,02)  CLI_READY
		// here we have to send supported families
		// see SNAC(01,17)
		//******************************************************
		// Generic service controls
		$snac_body =
		$this->split_byte(0x0001, 2).        // family number
		$this->split_byte(0x0004, 2).        // family version
		$this->split_byte(54752,  4).        // family dll version

		// ICBM (messages) service
		$this->split_byte(0x0004, 2).        // family number
		$this->split_byte(0x0001, 2).        // family version
		$this->split_byte(54752,  4)        // family dll version
		;

		$this->fsend($this->cons, 0x0005, $this->add_snac_header($snac_body, 0x0001, 0x0002, 0));
		//$this->fget();


		//sleep(1);

		// Disconnect from BOS Server
		//$this->close_connection();

		return true;
	}

	//******************************************************
	// Simply returns the error string
	// the error string is filled if a public-class
	// function failed
	//******************************************************
	/**
	 * Simply returns the error string.
	 *
	 * The error string is filled if a public-class
	 * function failed.
	 *
	 * @return string The formatted error string.
	 * @access public
	 */
	function get_error()
	{

		return $this->error;
	}


	/*function add_error($error) {

		if(isset($this->debug_funcs['add_error'])) {
			call_user_func($this->debug_funcs['add_error'], $debug);
		}

		$this->errors[] = $error;

	}*/

	/*function get_errors($delimeter = ',') {

		return implode($delimeter, $this->errors);

	}*/


	/**
	 * Sends a plain text message to the chosen uin thru the server
	 *
	 * It uses the server to send a message to the chosen contact. If
	 * the recipient is offline the server will store the message and sends
	 * it when comes online.
	 *
	 * @param string The recipient uin.
	 * @param string The message you want to send.
	 * @access public
	 */
	function send_message($target_userid, $message)
	{
		$message_data_tlv =
		$this->split_byte(0x05, 1).                                        // fragment identifier (array of required capabilities)
		$this->split_byte(0x01, 1).                                        // fragment version
		$this->split_byte(0x0001, 2).                                // Length of rest data
		$this->split_byte(0x01, 1).                                        // byte array of required capabilities (1 - text)

		$this->split_byte(0x01, 1).                                        // fragment identifier (array of required capabilities)
		$this->split_byte(0x01, 1).                                        // fragment version
		$this->split_byte(strlen($message) + 4, 2).        // Length of rest data
		$this->split_byte(0x0003, 2).                                // block char set
		$this->split_byte(0x0000, 2).                                // block char subset
		$message                                                                        // message text string
		;

		$snac_body =
		$this->split_byte(time() * 1000, 8).                                // msg-id cookie  (uptime of the computer)  // wrong not implemented, yet
		$this->split_byte(0x0001, 2).                                                // message channel
		$this->split_byte(strlen($target_userid), 1).                // screenname string length (reciepient)
		$target_userid.                                                                                // screenname string (reciepient)
		$this->make_tlv(0x0002, $message_data_tlv, 0).                // TLV.Type(0x02) - message data
		$this->make_tlv(0x0006, '', 0)                                                // TLV.Type(0x06) - store message if recipient offline
		;

		$this->fsend($this->add_snac_header($snac_body, 0x0004, 0x0006, 0));
	}


	function my_dechex($number) {

		$hex = dechex($number);
		if(strlen($hex) % 2) {
			$hex = "0" . $hex;
		}

		return $hex;

	}

	function hexlen($hex) {
		if(strlen($this->my_dechex(floor(strlen($hex)/ 2))) == 2) {
			return "00" . $this->my_dechex(floor(strlen($hex)/ 2));
		} else {
			return $this->my_dechex(floor(strlen($hex)/ 2));
		}
	}

	/**
	 * gets value of bytes in hex string and return them as normal bytes
	 *
	 * @param string $str
	 * @return string
	 */
	function chrit($str) {
		$t = "";
		for($i=0;$i<strlen($str);$i=$i+2)
		{
			$php_code="\$t.=chr(0x".substr($str,$i,2).");";
			eval($php_code);
		}
		return $t;
	}


	function _sms_body($number, $sms) {

		$time = gmdate("D, d M Y H:i:s", time());

		$return  = <<<XML
<icq_sms_message><destination>+{$number}</destination><text>{$sms}</text><encoding>utf8</encoding><senders_UIN>{$this->uin}</senders_UIN><senders_name>Icq</senders_name><delivery_receipt>Yes</delivery_receipt><time>{$time} GMT</time><ICQVersion>prili</ICQVersion><ICQBuildID>1094</ICQBuildID></icq_sms_message>
XML;

		return $return;
	}

	/**
	 * Sending SMS message to the given phone number
	 *
	 * @param string the cellphone number
	 * @param string the sms message body
	 * @access public
	 */
	function send_sms($number , $sms) {
		
		$this->errors = array();
		$this->error = "";
		
		$raw = '';
		$dao = '';

		$raw = $this->chrit($this->revhex($this->my_dechex($this->uin), 8)) .
		$this->chrit($this->revhex($this->my_dechex("2000"), 4)).
		$this->chrit($this->revhex($this->my_dechex("15758"), 4));

		$raw .= $this->chrit("821400010016000000000000000000000000000000000000");

		$xml = $this->_sms_body($number, $sms) . chr(0x00);

		if( strlen($this->my_dechex( (int)floor(strlen($xml)) )) == 2) {
			$dao = "00" . $this->my_dechex( strlen($xml) );
		} else {
			$dao = $this->my_dechex(strlen($xml));
		}
		//XML meassage size
		$xml = $raw . $this->chrit($dao) . $xml;

		if(strlen($this->my_dechex((int)floor(strlen($xml)))) == 2) {

			$dao = "00" . $this->my_dechex(((int)floor(strlen($xml))));
		}
		else
		{
			$dao = $this->my_dechex((int)floor(strlen($xml)));
		}
		//chunk size
		$xml = $this->chrit($this->revhex($dao, 4)) . $xml;
		$sms_snac = $this->add_snac_header(
		$this->make_tlv(0x01, $xml, 0), 0x0015, 0x002, 0
		);

		$this->fsend($this->cons, 0x0005, $sms_snac);

		$this->fget();
		
		$flaps = count($this->packet_reader->packets);
		
		
		$snac_info['fam'] = false;
		$snac_info['sub'] = false;
		
		for($i = 0; $i < $flaps; $i++) {
			
		
			$this->set_readFrom($this->packet_reader->packets[$i]->data);
			$flap_length = $this->check_flap_header(FLAP_CHANNEL_SNAC_DATA);
			$snac_info = $this->read_snac_header();
			//print_r($snac_info);
			if($snac_info['fam'] == 0x0015 && $snac_info['sub'] == 0x0003) {
				break;
			}
			
		}
		//print_r($snac_info);
		if($snac_info['fam'] != 0x0015 || $snac_info['sub'] != 0x0003) {
			
			$this->fget();
			$flaps = count($this->packet_reader->packets);
		
			for($i = 0; $i < $flaps; $i++) {
				
			
				$this->set_readFrom($this->packet_reader->packets[$i]->data);
				$flap_length = $this->check_flap_header(FLAP_CHANNEL_SNAC_DATA);
				$snac_info = $this->read_snac_header();
				//print_r($snac_info);
				if($snac_info['fam'] == 0x0015 && $snac_info['sub'] == 0x0003) {
					break;
				}
					
			}
			
			if($snac_info['fam'] != 0x0015 || $snac_info['sub'] != 0x0003) {
				$this->add_error("Got different snac then expected:fam({$snac_info['fam']}),sub({$snac_info['sub']})");
			}
						
		}





		// Read TLV id
		$tlv_id = $this->fget_word();
		// Read length of the TLV value
		$tlv_length = $this->fget_word();


		/*get ride of the unimportent information

		xx xx 	  	word (LE) 	  	data chunk size (TLV.Length-2)
		xx xx xx xx 	  	dword (LE) 	  	request owner uin
		DA 07 	  	word (LE) 	  	cmd: META_DATA
		02 00 	  	word (LE) 	  	request sequence number

		*/
		$this->fget_dummy_bytes(10);

		//get the subcmd

		$subcmd = $this->fget_string(2);

		/* Lets see if its META_PROCESSING_ERROR or META_SMS_RECEIPT

		0100 or 9600

		*/

		if($subcmd == $this->chrit("0100")) {

			//we are in META_PROCESSING_ERROR ):

			$error_code = 0;
			$error_str = '';
			$error_code = $this->fget_byte();

			$error_str = $this->fget_string($tlv_length - 14);

			$this->error = "{$error_str}, code:{$error_code}";
			
			if(preg_match('#The Cellular network is#', $error_str)) {
				
				$this->error = "הרשת הסלולרית שאליה אתה מנסה לשלוח את ההודעה אינה תומכת בהודעות מהICQ או שהיא אינה זמינה כרגע";

			}
			
			$this->add_error($this->error);
			
			return false;

		}

		//we are in META_SMS_RECEIPT!

		/*

		I dont need this:
		0A 	  	char 	  	success byte
		00 01 	  	word 	  	unknown field
		00 0d 	  	word 	  	unknown field
		00 0b 	  	word 	  	unknown field

		*/



		$this->fget_dummy_bytes(9);

		//the receipt length

		$resp_xml_length = $this->fget_word();

		//read the xml

		$resp_xml = $this->fget_string($resp_xml_length);

		//First, i want to see if the sms sent
//		file_put_contents("c:/log/s" . time(),print_r($this->in_packets, 1));
		if(strpos($resp_xml, "<deliverable>Yes</deliverable>")) {
			
			return true;

		} else if(strpos($resp_xml, "<deliverable>No</deliverable>")) {
			echo "asdfasdfsadfdsa";
			$error_str = array();
			preg_match("#<param>(.*)</param>#i", $resp_xml, $error_str);
			print_r($error_str);
			if(preg_match('#The Cellular network is#', $error_str[1])) {

				$this->error = "הרשת הסלולרית שאליה אתה מנסה לשלוח את ההודעה אינה תומכת בהודעות מהICQ";
				$this->add_error($this->error);
				return false;
			} else {
				$this->error = $error_str[1];
				$this->add_error($this->error);
			}

		} else {
			
			$this->error = 'resp protocol error ';
			$this->fget();
			$this->add_error($this->error);

		}

		return false;

	}




}
?>