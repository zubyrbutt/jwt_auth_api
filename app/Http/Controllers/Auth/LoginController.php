<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

class LoginController extends Controller
{

    use AuthenticatesUsers;

    protected function attemptLogin(Request $request){

        //attempt to issue login token to the user base on credentials
        $token = $this->guard()->attempt($this->credentials($request));

        //check if token issue
        if(! $token){
            return false;
        }

        //Get authenticate user
        $user = $this->guard()->user();

        //check user email verified or not
        if($user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail()){
            return false;
        }

        //if all of these verified then issue the login
        //set the user token
        $this->guard()->setToken($token);
        return true;
    }
    protected function sendLoginResponse(Request $request){
        $this->clearLoginAttempts($request);

        //get the token form authentication guard (JWT)
        $token = (string)$this->guard()->getToken();

        //extract the expiry date of the token
        $expiration = $this->guard()->getPayload()->get('exp');

        //get the response
        return response()->json([
            'token' => $token,
            'token_type' => 'bearer',
            'expire_in' => $expiration
        ]);
    }
    protected function sendFailedLoginResponse(Request $request)
    {
       $user =  $this->guard()->user();
       if($user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail()){
           return response()->json(["errors" =>[
               "Verification" => 'you must to verify your email address ..'
           ]

           ]);
       }
        throw ValidationException::withMessages([$this->username() => 'credentials not match ..']);
    }

    //for user logout

    public function logout(Request $request)
    {
        $this->guard()->logout();
        return response()->json(['message' => 'user logout successfully!']);
    }

}
