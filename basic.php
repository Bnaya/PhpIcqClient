<?php
//lalaal
class basic {

	var $errors;

	function add_error($error, $level = 1) {

		$debug = debug_backtrace();

			$this->errors[] = $error;


			$er = mysql_real_escape_string($error);
			if($level == 0) {
				sql_query(sprintf("INSERT INTO `errors_log` (`backtrace`, `error_string`, `level`, `in_function`, `line` ) VALUES ('%s', '%s', '%s', '%s', '%s')", 
				mysql_real_escape_string(print_r($debug ,true)), $er, $level, mysql_real_escape_string($debug[1]['function']), mysql_real_escape_string($debug[1]['line'])));
			}
		
	}
	
	function get_errors($delimeter = ',') {
		
		return implode($delimeter, $this->errors);
		
	}

	
}
?>