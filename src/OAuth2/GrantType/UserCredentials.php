<?php

namespace OAuth2\GrantType;

use OAuth2\Storage\UserCredentialsInterface;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class UserCredentials implements GrantTypeInterface
{
    private $userInfo;

    protected $storage;

    /**
     * @param OAuth2\Storage\UserCredentialsInterface $storage REQUIRED Storage class for retrieving user credentials information
     */
    public function __construct(UserCredentialsInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier()
    {
        return 'password';
    }

    private function printToLog($msg){
        error_log($msg . PHP_EOL, 3, "/tmp/testlog.dat");
    }

    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        //determines whether the user is coming from Magnolia or the form
        $isFormRequest = !is_null($request->request("formLogin"));

        if (!$request->request("password") || !$request->request("username")) {
            $response->setError(400, 'invalid_request', 'Missing parameters: "username" and "password" required');

            return null;
        }
        //$this->printToLog("executing UserCredentials validateRequest");
	//$this->printToLog("username = " . $request->request("username"));
	//$this->printToLog("password = " . $request->request("password"));
/*echo "username = " . $request->request("username");
echo "\npassword = " . $request->request("password") . "\n";
return;*/
        //ONLY CHECK CREDENTIALS IF THEY WERE SENT FROM MAGNOLIA AND NOT ENTERED BY FORM
        //$this->printToLog("formLogin = " . $request->request("formLogin") . " user = " . $request->request("username"));
        if(!$isFormRequest){
        //user credentials coming from Magnolia
                if (!$this->storage->checkUserCredentials($request->request("username"), $request->request("password"))) {
                $response->setError(401, 'invalid_grant', 'Invalid username and password combination');

                return null;
            }
        }

        $userInfo = $this->storage->getUserDetails($request->request("username"));

        if (empty($userInfo)) {
            $response->setError(400, 'invalid_grant', 'Unable to retrieve user information');

            return null;
        }

        if (!isset($userInfo['user_id'])) {
            throw new \LogicException("you must set the user_id on the array returned by getUserDetails");
        }

        $this->userInfo = $userInfo;

        //$this->printToLog("PRINTING USERINFO RIGHT NOW ROLE = " . $this->getRole());
        //file_put_contents('/tmp/userinfo.txt', print_r($userInfo, true));

        //$this->printToLog("executing UserCredentials validation");
        //if the user credentials were entered by form then token.php?formLogin=t will be invoked
        if($isFormRequest){
            //$this->printToLog("inside formLogin block pwd = " . $userInfo["password"]);
            //GET THE USER DETAILS FROM OAUTH_USERS TABLE
            //file_put_contents("/tmp/userarray.dat", print_r($userInfo, true), FILE_APPEND);

            //VERIFY THE USER'S PASSWORD HASH FROM DB AGAINST THE PASSWORD RECEIVED IN THE FORM
            if(!password_verify($request->request("password"), $userInfo["password"])){
                //$this->printToLog("Password is Nok");
                $response->setError(401, 'invalid_grant', 'Invalid username and password combination');
                return false;
            }

            //$this->printToLog("Password is OK");
        }

        return true;
    }

    public function getClientId()
    {
        return null;
    }

    public function getUserId()
    {
        return $this->userInfo['user_id'];
    }

    public function getScope()
    {
        return isset($this->userInfo['scope']) ? $this->userInfo['scope'] : null;
    }

    public function getRole(){
        return $this->userInfo["role"];
    }

    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope, $role)
    {
        return $accessToken->createAccessToken($client_id, $user_id, $scope, true , $role);
    }
}
