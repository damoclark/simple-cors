# SimpleCors

## Overview

A simple library providing cross-origin resource sharing (CORS) validation.  The library is not tethered to any
particular framework, and has only one dependency.

CORS configuration is defined through an `ini` file, the path to which can be determined from a configurable
web server environment variable.

## Installation

Require `damoclark/simple-cors` using composer. 

## Simple Usage

Prepare an `ini` file with your CORS security configuration:

```ini
; https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
; Access-Control-Allow-Headers: <header-name>, <header-name>, ...
allowedHeaders[] = 'X-HEADER'

; https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods
; Access-Control-Allow-Methods: <method>, <method>, ...
allowedMethods = 'GET,POST'

; https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
; Access-Control-Allow-Origin: *
; Access-Control-Allow-Origin: <origin>
allowedOrigins = '*'

; https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers
; Access-Control-Expose-Headers: <header-name>, <header-name>, ...
; exposedHeaders[] = ...

; Access-Control-Max-Age: <delta-seconds>
; maxAge = 86400 <- 1 day
maxAge = 86400

; https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
; Access-Control-Allow-Credentials: true
supportsCredentials = true
```

Set the environment variable `CORSCONF` via your webserver configuration:

```apacheconfig
<VirtualHost *>
	...
	SetEnv CORSCONF "/path/to/cors.ini"
	...
</VirtualHost>
```

Add the following lines to the start of your script (after you require your composer autoloader)

```php
// Respond with cors headers (where path to config ini file is stored in `CORSCONF` environment variable)
$cors = new \damoclark\SimpleCors\SimpleCors() ;


$cors->handle() or exit() ;
```

The `handle()` method will return true if your script should continue.  Such situations include:

* It is a valid CORS request
* It is not a CORS request

While the method will return false in the following situations:

* When the method isn't permitted
* When the origin isn't permitted
* When the requested header isn't permitted
* When it is a preflight request (OPTIONS request method)

In the last case (preflight), the `handle()` method will have already sent back response headers
to the client, so your script can still safely terminate this point, as per the example

If you do not wish for your script to continue if it is not a CORS request, then use the following pattern:

```php
// Respond with cors headers (where path to config ini file is stored in `CORSCONF` environment variable)
$cors = new \damoclark\SimpleCors\SimpleCors() ;

$cors->isCorsRequest() or exit() ;

$cors->handle() or exit() ;
```

## Contribution

Contributions (via Pull Requests) are welcome.

## Licence

Copyright (c) 2017 Damien Clark, [Damo's World](https://damos.world)<br/> <br/>
Licenced under the terms of the
[LGPLv3](https://www.gnu.org/licenses/lgpl.txt)<br/>
![LGPLv3](https://www.gnu.org/graphics/lgplv3-147x51.png "LGPLv3")

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL DAMIEN CLARK BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

