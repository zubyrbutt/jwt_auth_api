<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;

use Illuminate\Auth\Events\Verified;
use Illuminate\Foundation\Auth\VerifiesEmails;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\URL;


class VerificationController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Email Verification Controller
    |--------------------------------------------------------------------------
    |
    | This controller is responsible for handling email verification for any
    | user that recently registered with the application. Emails may also
    | be re-sent if the user didn't receive the original email message.
    |
    */

    use VerifiesEmails;


    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {

        $this->middleware('signed')->only('verify');
        $this->middleware('throttle:6,1')->only('verify', 'resend');
    }

    public function verify(Request $request, User $user)
    {
        // check if the link is valid signature
        if(! URL::hasValidSignature($request)){
            return response()->json(["error" => [
                "message" => "Link not valid please try again"
            ]], 422);
        }
        //check if the email id already verified

        if($user->hasVerifiedEmail()){
            return response()->json(["error" => [
                "message" => "This email already verified.."
            ]], 422);
        }
        $user->markEmailAsVerified();
        event(new Verified($user));
        return response()->json(['message'=>'email successfully verified..'], 200);

    }

    public function resend(Request $request)
    {

    }
}
