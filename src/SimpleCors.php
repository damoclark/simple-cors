<?php
/**
 * Created by PhpStorm.
 * User: clarkd
 * Date: 3/10/17
 * Time: 12:38 PM
 */

namespace damoclark\SimpleCors;


class SimpleCors
{

	private $options        = array(
	 'allowedHeaders'      => array(),
	 'allowedMethods'      => array(),
	 'allowedOrigins'      => array(),
	 'exposedHeaders'      => false,
	 'maxAge'              => false,
	 'supportsCredentials' => false
	);

	private $headers = array();

	private $varname = null ;

	private $configPath = null ;

	public function __construct($varname = 'CORSCONF')
	{
		if($varname != null)
		{
			$this->varname = $varname ;
			$this->configPath = getenv($varname) ;
			$this->options = $this->normaliseOptions($this->loadConfigFile($this->configPath)) ;
			$this->setRequestHeaders() ;
		}
	}

	public function loadConfigFile($configFilename)
	{
		if($configFilename == null)
			throw new \Exception("No configFile specified.  Dont know where to read parameters from") ;

		if(!is_file($configFilename) or !is_readable($configFilename))
			throw new \Exception("Config file '" . $configFilename . "' does not exist, is not readable, or is not a file") ;

		$config = parse_ini_file($configFilename) ;

		if($config === false)
			throw new \Exception("Error parsing config file '" . $configFilename . "'") ;

		//Save the config data structure
		return $config ;
	}

	public function isRequestAllowed()
	{
		return !$this->isCorsRequest() or $this->checkOrigin();
	}

	public function isCorsRequest()
	{
		return $this->hasHeader('Origin') && !$this->isSameHost();
	}

	public function isPreflightRequest()
	{
		return $this->isCorsRequest()
		 && $_SERVER['REQUEST_METHOD'] === 'OPTIONS'
		 && $this->hasHeader('Access-Control-Request-Method') ;
	}

	public function handlePreflightRequest()
	{
		if(!$this->isCorsRequest())
			return true ;

		if (true !== $check = $this->checkCORSRequestConditions()) {
			return $check;
		}

		return $this->sendPreflightResponseHeaders();
	}

	/**
	 * Handle the request processing all aspects of CORS
	 *
	 * @return bool Returns true if script should continue otherwise false
	 */
	public function handle()
	{
		if(!$this->isCorsRequest())
			return true ;

		if($this->isPreflightRequest()) {
			$this->handlePreflightRequest() ;
			return false ; // If preflight, should not continue no matter what
		}
		return $this->handlePreflightRequest();
	}

	/**
	 * Set the request headers for this instance
	 *
	 * This method is automatically called by the constructor and will by default call
	 * the getallheaders() function.  It can however be overridden with a subclass or
	 * called manually providing an arbitrary array of headers to process
	 *
	 * @param array $headers An array of headers in the same format as produced by getallheaders() function
	 */
	protected function setRequestHeaders($headers = null)
	{
		if(is_null($headers))
			$this->headers = $this->getallheaders();
		else
			$this->headers = $headers ;
	}

	private function normaliseOptions(array $options = array())
	{
		$options = array_merge($this->options, $options);

		// normalize array('*') to true
		if(!is_array($options['allowedOrigins'])) {
			$options['allowedOrigins'] = preg_split('/\s*,\s*/',$options['allowedOrigins'],null,PREG_SPLIT_NO_EMPTY) ;
		}
		if (in_array('*', $options['allowedOrigins'])) {
			$options['allowedOrigins'] = true;
		}

		if(!is_array($options['allowedHeaders'])) {
			$options['allowedHeaders'] = preg_split('/\s*,\s*/',$options['allowedHeaders'],null,PREG_SPLIT_NO_EMPTY) ;
		}
		if (in_array('*', $options['allowedHeaders'])) {
			$options['allowedHeaders'] = true;
		} else {
			$options['allowedHeaders'] = array_map('strtolower', $options['allowedHeaders']);
		}

		if(!is_array($options['allowedMethods'])) {
			$options['allowedMethods'] = preg_split('/\s*,\s*/',$options['allowedMethods'],null,PREG_SPLIT_NO_EMPTY) ;
		}
		if (in_array('*', $options['allowedMethods'])) {
			$options['allowedMethods'] = true;
		} else {
			$options['allowedMethods'] = array_map('strtoupper', $options['allowedMethods']);
		}

		return $options;
	}

	public function sendResponseHeaders()
	{
		if(!$this->sendPreflightResponseHeaders())
			return false ;

		if ($this->options['exposedHeaders']) {
			header("Access-Control-Expose-Headers: {implode(', ', $this->options['exposedHeaders'])}");
		}
	}

	private function sendPreflightResponseHeaders()
	{
		if ($this->options['supportsCredentials']) {
			header('Access-Control-Allow-Credentials: true') ;
		}

		header("Access-Control-Allow-Origin: {$this->getHeader('Origin')}");

		if ($this->options['maxAge']) {
			header("Access-Control-Max-Age: {$this->options['maxAge']}");
		}

		$allowMethods = $this->options['allowedMethods'] === true
		 ? strtoupper($this->getHeader('Access-Control-Request-Method'))
		 : implode(', ', $this->options['allowedMethods']);
		header("Access-Control-Allow-Methods: $allowMethods");

		$allowHeaders = $this->options['allowedHeaders'] === true
		 ? strtoupper($this->getHeader('Access-Control-Request-Headers'))
		 : implode(', ', $this->options['allowedHeaders']);
		if($allowHeaders != '')
			header("Access-Control-Allow-Headers: $allowHeaders");

		return true;
	}

	private function checkCORSRequestConditions()
	{
		if (!$this->checkOrigin()) {
			error_log("SimpleCors: Bad Origin") ;
			return $this->sendBadRequestResponse(403);
		}

		if (!$this->checkMethod()) {
			error_log("SimpleCors: Bad Method") ;
			return $this->sendBadRequestResponse(405);
		}

		$requestHeaders = array();
		// if allowedHeaders has been set to true ('*' allow all flag) just skip this check
		if ($this->options['allowedHeaders'] !== true && $this->hasHeader('Access-Control-Request-Headers')) {
			$headers        = strtolower($this->getHeader('Access-Control-Request-Headers'));
			$requestHeaders = array_filter(explode(',', $headers));

			foreach ($requestHeaders as $header) {
				if (!in_array(trim($header), $this->options['allowedHeaders'])) {
					error_log("SimpleCors: Disallowed header") ;
					return $this->sendBadRequestResponse(403) ;
				}
			}
		}

		return true;
	}

	private function sendBadRequestResponse($code)
	{
		http_response_code($code) ;
		return false ;
	}

	private function isSameHost()
	{
		$url = parse_url($_SERVER['REQUEST_URI']) ;
		$schemeAndHost = "{$url['scheme']}://{$url['host']}" ;
		return $this->getHeader('Origin') === $schemeAndHost;
	}

	private function checkOrigin()
	{
		if ($this->options['allowedOrigins'] === true) {
			// allow all '*' flag
			return true;
		}
		$origin = $this->getOrigin();

		return in_array($origin, $this->options['allowedOrigins']);
	}

	private function checkMethod()
	{
		if ($this->options['allowedMethods'] === true) {
			// allow all '*' flag
			return true;
		}

		$requestMethod = $this->getHeader('Access-Control-Request-Method');
		if($requestMethod !== '')
			return in_array($requestMethod, $this->options['allowedMethods']);

		// Not preflight, so use the REQUESTED METHOD of this request
		return in_array($_SERVER['REQUEST_METHOD'], $this->options['allowedMethods']);
	}

	private function getOrigin()
	{
		return $_SERVER['HTTP_ORIGIN'];
	}

	private function hasHeader($header)
	{
		return array_key_exists($header,$this->headers) ;
	}

	private function getHeader($header)
	{
		if(!$this->hasHeader($header,$this->headers))
			return '' ;

		return $this->headers[$header] ;
	}

	private function getallheaders()
	{
		if (!is_array($_SERVER)) {
			return array();
		}

		$headers = array();
		foreach ($_SERVER as $name => $value) {
			if (substr($name, 0, 5) == 'HTTP_') {
				$headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
			}
		}
		return $headers;
	}

}