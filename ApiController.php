<?php
/*-----------------------------------------------------------------------------------
@Author -Ambuj Mishra
@Created Date -25/08/2022
-----------------------------------------------------------------------------------*/

namespace App\Http\Controllers;

use App\Models\ApiModel;
use Config;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class ApiController extends Controller
{

    //--------------------------------- DB Instance---------------------------------
    private $api_model;

    //------------------------------------External Api----------------------------------

    public function __construct()
    {
        $this->api_model = new ApiModel();
    }

    public function uniqueId()
    {
        $str = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNIPQRSTUVWXYZ';
        $nstr = str_shuffle($str);
        $unique_id = substr($nstr, 0, 10);
        return $unique_id;
    }

    public function genrateToken()
    {
        $token = openssl_random_pseudo_bytes(16);
        $token = bin2hex($token);
        return $token;
    }

    //-------------------------- for single upload File-------------------------------
    public function singleUpload($request, $file_name, $path)
    {
        if ($request->hasfile($file_name)) {
            $file = $request->file($file_name);
            $name = time() . '.' . $file->extension();
            sleep(1);
            $file->move(base_path('uploads/') . $path, $name);
            return $name;
        } else {
            return false;
        }
    }
    //----------------------------------Fot Multiple Files---------------------------
    public function multipleUploads($request, $file_name, $path)
    {
        if ($request->hasfile($file_name)) {
            $data = [];
            foreach ($request->file($file_name) as $file) {
                $name = time() . '.' . $file->extension();
                sleep(1);
                $file->move(base_path('uploads/') . $path, $name);
                $data[] = $name;
            }
            return $data;
        } else {
            return false;
        }
    }

    public function genrateOtp()
    {
        return 1234;
        //return rand(1111, 9999);
    }

    //-------------------------------------------------Mail---------------------------------------
    public function sendMail($data, $view)
    {

        $htmlContent = view('mail/' . $view, $data)->render();
        $from = "admin@scalie.io";
        $to = $data['email'];
        $subject = $data['subject'];
        $headers = 'MIME-Version: 1.0' . "\r\n";
        $headers .= 'Content-type: text/html; charset=iso-8859-1' . "\r\n";
        $headers .= 'From: ' . $from . "\r\n";
        @mail($to, $subject, $htmlContent, $headers);
        return false;
    }

    public function register(Request $request)
    {

        $requestdata = $request->all();
        $validator = Validator::make($requestdata, [
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'country_code' => 'required',
            'phone' => 'required',
            'password' => 'required|min:6',
            'confirm_password' => 'required|same:password|min:6',
            'terms' => 'required',
            'privacy' => 'required',

        ], [
            'required' => 'This :Attribute is Required',
            'privacy.required' => 'You Must Accept Privacy And Po;licy',
            'terms.required' => 'You Must Accept Terms And Condtion',
        ]);
        if ($validator->fails()) {
            return response()->json(['result' => 0, 'errors' => $validator->errors()->first()]);
            return false;
        }
        //$otp = $this->genrateOtp();
        $otp = 1234;
        $insertdata = array(
            'name' => $requestdata['name'],
            'email' => $requestdata['email'],
            'country_code' => $requestdata['country_code'],
            'mobile' => $requestdata['phone'],
            'password' => hash('sha256', $request['password']),
            'terms' => $requestdata['terms'],
            'privacy' => $requestdata['privacy'],
            'otp' => $otp,
        );
        $device_type = $request->post('device_type');
        $result = $this->api_model->doRegister($insertdata, $device_type);
        if ($result) {
            $data = $this->api_model->getUserByID($result);
            // verification otp mail
            $maildata['name'] = $data->name;
            $maildata['email'] = $data->email;
            $maildata['message'] = 'Your verification Otp is ' . $otp;
            $maildata['subject'] = 'Otp Verifiation mail !!';
            $this->sendMail($maildata, 'otpmail');

            return response()->json(['result' => 1, "msg" => "Registration Successfully.We have sent you an otp on email. please verify yourself !!", 'data' => $data]);
        } else {
            return response()->json(['result' => -1, "msg" => "Something went Wrong", 'data' => null]);
        }
    }
    public function register1(Request $request)
    {

        $requestdata = $request->all();
        // $validator = Validator::make($requestdata, [
        //     'name' => 'required',
        //     'email' => 'required|email|unique:users',
        //     'country_code' => 'required',
        //     'phone' => 'required',
        //     'password' => 'required|min:6',
        //     'confirm_password' => 'required|same:password|min:6',
        //     'terms' => 'required',
        //     'privacy' => 'required',

        // ], [
        //     'required' => 'This :Attribute is Required',
        //     'privacy.required' => 'You Must Accept Privacy And Po;licy',
        //     'terms.required' => 'You Must Accept Terms And Condtion',
        // ]);
        // if ($validator->fails()) {
        //     return response()->json(['result' => 0, 'errors' => $validator->errors()->first()]);
        //     return false;
        // }
        //$otp = $this->genrateOtp();
        $otp = 1234;
        $insertdata = array(
            'name' => $requestdata['name'],
            'email' => $requestdata['email'],
            'country_code' => $requestdata['country_code'],
            'mobile' => $requestdata['phone'],
            'password' => hash('sha256', $request['password']),
            'terms' => 'yes',
            'privacy' => 'yes',
            'otp' => $otp,
        );
        $device_type = $request->post('device_type');
        $result = $this->api_model->doRegister($insertdata, $device_type);
        if ($result) {
            $data = $this->api_model->getUserByID($result);
            // verification otp mail
            $maildata['name'] = $data->name;
            $maildata['email'] = $data->email;
            $maildata['message'] = 'Your verification Otp is ' . $otp;
            $maildata['subject'] = 'Otp Verifiation mail !!';
            $this->sendMail($maildata, 'otpmail');

            return response()->json(['result' => 1, "msg" => "Registration Successfully.We have sent you an otp on email. please verify yourself !!", 'data' => $data]);
        } else {
            return response()->json(['result' => -1, "msg" => "Something went Wrong", 'data' => null]);
        }
    }

    public function login(Request $request)
    {
        $requestdata = $request->all();
        $validator = Validator::make($requestdata, [
            'email' => 'required|email',
            'password' => 'required|min:6',
        ], [
            'required' => 'This :Attribute is Required',
        ]);
        if ($validator->fails()) {
            return response()->json(['result' => 0, 'errors' => $validator->errors()->first()]);
            return false;
        }
        $email = $request->post('email');
        $password = hash('sha256', $request->post('password'));
        $checkemail = $this->api_model->getUserByEmail($email);
        if (!empty($checkemail)) {
            if ($checkemail->is_verified == 'no') {
                // verifacation mail
                // verification otp mail
                $maildata['name'] = $checkemail->name;
                $maildata['email'] = $checkemail->email;
                $maildata['message'] = 'Your verification Otp is ' . $this->genrateOtp();
                $maildata['subject'] = 'Otp Verifiation mail !!';
                $this->sendMail($maildata, 'otpmail');
                header('HTTP/1.1 402 User Account has not been verified yet.', true, 402);
                return response()->json(['result' => -2, 'msg' => 'Please verify Yourself We have resend verification link to your email id. Please check your mail.'], 401);
                return false;
            }
            if ($checkemail->status == 'Deleted') {
                header('HTTP/1.1 402 User Account has been deleted.', true, 402);
                return response()->json(['result' => -2, 'msg' => 'Your account has been deleted.'], 401);
                return false;
            }
            if ($checkemail->status == 'Blocked') {
                header('HTTP/1.1 402 User Account Is Blocked.', true, 402);
                return response()->json(['result' => -2, 'msg' => 'Your account is blocked.'], 401);
                return false;
            }
            if ($checkemail->status == 'Inactive') {
                header('HTTP/1.1 402 User Account Is Inactive.', true, 402);
                return response()->json(['result' => -2, 'msg' => 'Your account has been inactive by admin.'], 401);
                return false;
            }
        } else {
            return response()->json(['result' => -1, 'msg' => 'Email does not exist'], 401);
            return false;
        }
        $results = $this->api_model->doLogin($email, $password);
        if ($results) {
            if ($results->is_verified == 'no') {
                return response()->json(['result' => 3, 'msg' => 'Please Verfiy yourself', 'data' => $results]);
                return false;
            }
            $this->api_model->updateToken($results->user_id, $this->genrateToken());
            $result = $this->api_model->getUserByID($results->user_id);
            return response()->json(['result' => 1, 'msg' => 'Login Successfully', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'Email id or password is incorrect.', 'data' => null]);
            return false;
        }
    }

    public function getUserBYtokenOrUserID(Request $request)
    {
        $token = $request->header('token');
        $user_id = $request->post('user_id');
        if (empty($user_id)) {
            if (empty($token)) {
                return response()->json(['result' => -1, "msg" => "Please Provide User Token or User id"]);
            }
        } elseif (empty($token)) {
            if (empty($user_id)) {
                return response()->json(['result' => -1, "msg" => "Please Provide User Token or User id"]);
            }
        }
        if (!empty($token)) {
            $result = $this->api_model->getUserByToken($token);
        }
        if (!empty($user_id)) {
            $result = $this->api_model->getUserByID($user_id);
        }
        if ($result) {
            return response()->json(['result' => 1, "msg" => "Data Fetched Successfully !!", 'data' => $result]);
        } else {
            return response()->json(['result' => -1, "msg" => "Something went Wrong", 'data' => null]);
        }
    }

    public function sendOtp(Request $request)
    {
        $email = $request->post('email');
        $is_email = $this->api_model->getUserByEmail($email);
        if (empty($is_email)) {
            return response()->json(['result' => -1, 'msg' => 'Email is not present in our database.']);
            return false;
        }
        $otp = $this->genrateOtp();
        $result = $this->api_model->sendOtp($otp, $is_email->user_id);
        if ($result) {
            // Send otp mail
            $result = $this->api_model->getUserByID($is_email->user_id);
            $maildata['name'] = $result->name;
            $maildata['email'] = $result->email;
            $maildata['message'] = 'Your  Otp is ' . $otp;
            $maildata['subject'] = 'Otp  mail !!';
            $this->sendMail($maildata, 'otpmail');

            return response()->json((['result' => 1, 'msg' => 'Otp Send Successfully', 'data' => $result]));
        } else {
            return response()->json((['result' => -1, 'msg' => 'Failed to send otp.']));
        }
    }

    public function otpVerification(Request $request)
    {
        $user_id = $request->post('user_id');
        $otp = $request->post('otp');
        if (empty($user_id)) {
            return response()->json(['result' => -1, 'msg' => 'User ID is Required!!.']);
            return false;
        }
        if (empty($otp)) {
            return response()->json(['result' => -1, 'msg' => 'Otp Required.']);
            return false;
        }
        //$current_time = date('Y-m-d h:i');
        $result = $this->api_model->verifyOtp($otp, $user_id);
        if ($result) {
            // if (strtotime($result['otp_expiry']) < strtotime($current_time)) {
            //    return response()->json(['result' => -1, 'msg' => 'Otp Expired. Please Request New Otp']);
            //     return false;
            // }
            $this->api_model->updateVerifyStatus($user_id);
            $result = $this->api_model->getUserByID($user_id);
            return response()->json(['result' => 1, 'msg' => 'Otp Verified Successfully.', 'data' => $result]);
        } else {
            return response()->json(['result' => -1, 'msg' => 'Invaid Otp.']);
        }
    }

    public function forgotPassword(Request $request)
    {
        $email = $request->post('email');
        if (empty($email)) {
            return response()->json(['result' => 0, 'msg' => 'Email is Required!!!.']);
            return false;
        }
        $mail_exist = $this->api_model->getUserByEmail($email);
        if ($mail_exist) {
            $result = $this->api_model->getUserByID($mail_exist->user_id);
            $otp = $this->genrateOtp();
            $maildata['name'] = $result->name;
            $maildata['email'] = $result->email;
            $maildata['message'] = 'Your  Otp is ' . $otp;
            $maildata['subject'] = 'Forgot Password !!';
            // $this->sendMail($maildata, 'otpmail');
            $result = $this->api_model->sendOtp($otp, $mail_exist->user_id);
            return response()->json(['result' => 1, 'msg' => 'Otp Sent on your mail.', 'data' => ['user_id' => $mail_exist->user_id, 'email' => $mail_exist->email, 'otp' => $otp]]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'User does not exist.', 'data' => null]);
            return false;
        }
    }

    public function resetPassword(Request $request)
    {
        $user_id = $request->post('user_id');
        $new_pass = $request->post('new_password');
        $c_pass = $request->post('confirm_password');
        if ($new_pass != $c_pass) {
            return response()->json(['result' => -1, 'msg' => 'Password should be same.']);
        } else {
            if ($new_pass == $c_pass) {
                $result = $this->api_model->resetPassword($user_id, $new_pass);
                if ($result) {
                    return response()->json(['result' => 1, 'msg' => 'Password reset successfully']);
                } else {
                    return response()->json(['result' => -1, 'msg' => 'You Are using old Password ! Please Login with same and chnage your password']);
                }
            } else {
                return response()->json(['result' => -1, 'msg' => 'New and Confirm password did not match.']);
            }
        }
    }

    public function changePassword(Request $request)
    {
        $user_token = $request->header('token');
        $user_data = $this->api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            return response()->json(['result' => -2, 'msg' => 'User already logged in on a different device'], 401);
            return false;
        }
        $user_id = $user_data->user_id;
        $old_pass = $request->post('old_password');
        $new_pass = $request->post('new_password');
        $c_pass = $request->post('confirm_password');
        if (empty($old_pass)) {
            return response()->json(['result' => -1, 'msg' => 'Old Password Cant be Empty.']);
        }
        if (empty($new_pass)) {
            return response()->json(['result' => -1, 'msg' => 'New Password Cant be Empty.']);
        }
        $checkold = $this->api_model->checkoldpassword($old_pass, $user_id);
        if ($checkold) {
            if ($old_pass == $new_pass) {
                return response()->json(['result' => -1, 'msg' => 'New and Old Password should not be same.']);
            } else {
                if ($new_pass == $c_pass) {
                    $result = $this->api_model->changePassword($user_id, $old_pass, $new_pass);
                    if ($result) {
                        return response()->json(['result' => 1, 'msg' => 'Password changed successfully']);
                    } else {
                        return response()->json(['result' => -1, 'msg' => 'Password Update Failed']);
                    }
                } else {
                    return response()->json(['result' => -1, 'msg' => 'New and Confirm password did not match.']);
                }
            }
        } else {
            return response()->json(['result' => -1, 'msg' => 'Old password is Incorrect.']);
        }
    }

    public function socialLogin(Request $request)
    {
        $social_type = $request->post('social_type');
        $name = $request->post('name');
        $email = $request->post('email');
        $social_id = $request->post('social_id');
        $device_type = $request->post('device_type');
        $checkemail = $this->api_model->getUserByEmail($email);
        if (!empty($checkemail)) {
            return response()->json(['result' => -1, 'msg' => 'You Have ALready Register With US please Login with your email and password .in case you forgot your password please reset it by forgot password.']);
        }
        $token = $this->genrateToken();
        $checkmail = $this->api_model->checkSocialUserData($email, $social_type);
        if (empty($checkmail)) {
            $insert_social_data = $this->api_model->insertSocialUserData($social_type, $email, $social_id, $name, $device_type);
        } else {
            if ($checkmail->status == 'Blocked') {
                return response()->json(['result' => 1, 'msg' => 'Your account has been blocked.', 'data' => null]);
                return false;
            } else {
                $update_social_data = $this->api_model->updateSocialUserData($social_type, $email, $social_id, $checkmail->user_id, $name, $device_type);
            }
        }
        $userdata = $this->api_model->checkSocialUserData($email, $social_type);
        return response()->json(['result' => 1, 'msg' => 'Logged In Successfully.', 'data' => $userdata]);
        return false;
    }

    public function updateProfile(Request $request)
    {
        $requestdata = $request->all();
        $user_token = $request->header('token');
        $user_data = $this->api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            return response()->json(['result' => -2, 'msg' => 'User already logged in on a different device'], 401);
            return false;
        }
        $user_id = $user_data->user_id;
        $validator = Validator::make($requestdata, [
            'name' => 'required',
            'country_code' => 'required',
            'phone' => 'required',
        ], [
            'required' => 'This :Attribute is Required',
        ]);
        if ($validator->fails()) {
            return response()->json(['result' => 0, 'errors' => $validator->errors()->first()]);
            return false;
        }
        // $otp = $this->genrateOtp();
        $otp = 1234;
        $updatedata = array(
            'name' => $requestdata['name'],
            'country_code' => $requestdata['country_code'],
            'mobile' => $requestdata['phone'],
        );
        $result = update('users', 'user_id', $user_id, $updatedata);
        $data = $this->api_model->getUserByID($user_id);
        if ($result) {
            return response()->json(['result' => 1, "msg" => "Profile Updated !!", 'data' => $data]);
        } else {
            return response()->json(['result' => 1, "msg" => "No Changes were found", 'data' => $data]);
        }
    }

    public function getSettingPage(Request $request)
    {
        $page = $request->post('page');
        if (empty($page)) {
            return response()->json(['result' => -1, "msg" => "Settings Page required !! "]);
        }
        $result = $this->api_model->getSettingPage($page);
        if ($result) {
            return response()->json(['result' => 1, "msg" => "Static Pages Content !!", 'data' => $result]);
        } else {
            return response()->json(['result' => 1, "msg" => "No Content were found"]);
        }
    }

    public function handbook()
    {
        $result = $this->api_model->getHandBook();
        if ($result) {
            return response()->json(['result' => 1, "msg" => "Hand Book Content !!", 'data' => $result]);
        } else {
            return response()->json(['result' => 1, "msg" => "No Content were found"]);
        }
    }
    // token base authentication  for firebase
    public function setFirebaseToken(Request $request)
    {
        $user_id = $request->post('user_id');
        $token_id = $request->post('firebase_token');
        $device_type = $request->post('device_type');
        $check = $this->api_model->checkfirebaseToken($token_id, $user_id);
        if ($check) {
            return response()->json(['result' => 0, 'msg' => 'Token Already Exists', 'data' => null]);
            return false;
        } else {
            $this->api_model->deleteFirebaseToken($user_id);
            $result = $this->api_model->updatefirebaseToken($token_id, $user_id, $device_type);
            if ($result) {
                return response()->json(['result' => 1, 'msg' => 'Token Id Updated']);
                return false;
            } else {
                return response()->json(['result' => -1, 'msg' => 'Fail To Update Token Id', 'data' => null]);
                return false;
            }
        }
    }

    public function sendNotfication(Request $request, $user_id, $body, $title, $data = null)
    {
        $token = $this->api_model->getToken($user_id);
        $api_key = Config::get('constant.API_ACCESS_KEY');
        $url = 'https://fcm.googleapis.com/fcm/send';
        $notification = array('title' => $title, 'body' => $body, 'sound' => 'default', 'badge' => '1');
        $arrayToSend = array('to' => $token['firebase_token'], 'notification' => $notification, 'priority' => 'high');
        $json = json_encode($arrayToSend);
        $headers = array();
        $headers[] = 'Content-Type: application/json';
        $headers[] = 'Authorization: key=' . $api_key;
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        //Send the request
        $response = curl_exec($ch);
        //Close reques

        if ($response === false) {
            die('FCM Send Error: ' . curl_error($ch));
        }
        curl_close($ch);
        // here is the notification send message
    }

    //--------------------------------------------Flight Releted API----------------------------------------------------------------
    public function caseType(Request $request)
    {
        $user_token = $request->header('token');
        $user_data = $this->api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            return response()->json(['result' => -2, 'msg' => 'User already logged in on a different device'], 401);
            return false;
        }
        if ($user_data->status == 'Inactive') {
            header('HTTP/1.1 402 User Account Is Inactive.', true, 402);
            return response()->json(['result' => -2, 'msg' => 'Your account has been inactive by admin.'], 401);
            return false;
        }
        $user_id = $user_data->user_id;
        $flight_relation_id = $this->uniqueId();
        $requestdata = $request->all();
        $validator = Validator::make($requestdata, [
            'case_type' => 'required',
        ], [
            'required' => 'This :Attribute is Required',
        ]);
        if ($validator->fails()) {
            return response()->json(['result' => 0, 'errors' => $validator->errors()->first()]);
            return false;
        }
        $refno = time() . rand(10 * 45, 100 * 98);
        $insertdata = array(
            'case_type' => $requestdata['case_type'],
            'user_id' => $user_id,
            'case_refrence_no' => 'Tawid' . $refno,
            'flight_relation_id' => $flight_relation_id,
            'submission_date' => date('Y-m-d h:i'),
            'status' => 'Inactive',
        );
        $result = $this->api_model->caseType($insertdata);
        if ($result) {
            return response()->json(['result' => 1, 'msg' => 'Case Details', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'Something Went Wrong please try again lator', 'data' => null]);
            return false;
        }
    }

    public function addPassenger(Request $request)
    {
        $requestdata = $request->all();
        $validator = Validator::make($requestdata, [
            'case_id' => 'required',
            'first_name' => 'required',
            'last_name' => 'required',
            'email' => 'required',
            'country_code' => 'required',
            'phone' => 'required',
            'city' => 'required',
            'country' => 'required',
            'flight_relation_id' => 'required',
        ], [
            'required' => 'This :Attribute is Required',
        ]);
        if ($validator->fails()) {
            return response()->json(['result' => 0, 'errors' => $validator->errors()->first()]);
            return false;
        }
        $flight_Relation_id = $request->post('flight_relation_id');
        //------------------------------------Back Form Functionality---------------------------------------
        $backform = $request->post('back_form');

        $insertdata = array(
            'case_id' => $requestdata['case_id'],
            'first_name' => $requestdata['first_name'],
            'last_name' => $requestdata['last_name'],
            'email' => $requestdata['email'],
            'country_code' => $requestdata['country_code'],
            'phone' => $requestdata['phone'],
            'city' => $requestdata['city'],
            'country' => $requestdata['country'],
            'date_of_birth' => str_replace('/', '-', date('Y-m-d', strtotime($requestdata['date_of_birth']))),
            'flight_relation_id' => $flight_Relation_id,
            'is_primary' => $requestdata['is_primary'],
        );
        // back form is passenger id
        if (!empty($backform)) {
            $result = $this->api_model->updatePassenger($insertdata, $backform);
        } else {
            $result = $this->api_model->addPassenger($insertdata);
        }
        if ($result) {
            return response()->json(['result' => 1, 'msg' => 'Passenger Data', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'Something Went Wrong please try again lator', 'data' => null]);
            return false;
        }
    }

    public function flightProcess(Request $request)
    {
        $requestdata = $request->all();
        $validator = Validator::make($requestdata, [
            'flight_type' => 'required',
            'departure_from' => 'required',
            'arrival_to' => 'required',
            'date_of_journey' => 'required',
            //'flight_number' => 'required',
            //'arrival_date' => 'required',
            //'arrival_time' => 'required',
            'delay_days' => 'required',
            'delay_reason' => 'required',
            'flight_relation_id' => 'required',
            'passenger_id' => 'required',
        ], [
            'required' => 'This :Attribute is Required',
        ]);
        if ($validator->fails()) {
            return response()->json(['result' => 0, 'errors' => $validator->errors()->first()]);
            return false;
        }
        $flight_relation_id = $request->post('flight_relation_id');
        // connecting Flight  details
        $connecting_flight = $request->post('connecting_flight');
        $connecting_flight_data = [];
        if ($connecting_flight == 'yes') {
            $connecting_flight_no = $request->post('connecting_flight_no');
            $connecting_flight_date_of_journey = $request->post('connecting_flight_date_of_journey');
            $i = 0;
            foreach ($connecting_flight_no as $cfno) {
                $temp['connecting_flight_no'] = $cfno;
                $temp['flight_relation_id'] = $flight_relation_id;
                $temp['connecting_flight_date_of_journey'] = str_replace('/', '-', date('Y-m-d', strtotime($connecting_flight_date_of_journey[$i])));
                array_push($connecting_flight_data, $temp);
                $temp = null;
                $i++;
            }
        }
        // Ticket Image Upload
        $ticket = $request->file('ticket');
        $ticket_images = null;
        if (empty($ticket)) {
            return response()->json(['result' => 0, 'errors' => 'Ticket Image Is Required']);
            return false;
        } else {
            $ticket_images = $this->multipleUploads($request, 'ticket', 'ticket');
        }
        $insertdata = array(
            'case_id' => $requestdata['case_id'],
            'type' => $requestdata['flight_type'],
            'connecting_flight' => $connecting_flight,
            'flight_relation_id' => $flight_relation_id,
            'airport_departure' => $requestdata['departure_from'],
            'airport_arrival' => $requestdata['arrival_to'],
            'date_of_journey' => str_replace('/', '-', date('Y-m-d', strtotime($requestdata['date_of_journey']))),
            'flight_number' => $requestdata['flight_number'],
            'flight_name' => $requestdata['flight_name'],
            'arrival_date' => str_replace('/', '-', date('Y-m-d', strtotime($requestdata['arrival_date']))),
            'arrival_time' => str_replace('/', '-', date('Y-m-d', strtotime($requestdata['arrival_time']))),
            'notify_days' => $requestdata['delay_days'],
            'reason' => $requestdata['delay_reason'],
            'flight_relation_id' => $requestdata['flight_relation_id'],
        );
        //------------------------------------Back Form Functionality---------------------------------------
        $backform = $request->post('back_form');
        // back form is passenger id
        if (!empty($backform)) {
            // first delted this data
            delete('connecting_flight_details', 'flight_relation_id', $flight_relation_id);
            $result = $this->api_model->updateflightProcess($insertdata, $flight_relation_id);
        } else {
            $count = count($this->api_model->getFlightDetailsByRelationId($flight_relation_id));
            if ($count == 0) {
                $result = $this->api_model->flightProcess($insertdata);
            } else {
                $result = $this->api_model->getFlightDetailsByRelationId($flight_relation_id)->first();
            }
        }
        if ($result) {
            $flight_number = $requestdata['flight_number'];
            $date = date('d.m.y');
            $reference_no = $flight_number . '-' . $date;
            $updatedata = array(
                'case_refrence_no' => $reference_no,
            );
            update('cases', 'flight_relation_id', $flight_relation_id, $updatedata);
            if (!empty($connecting_flight_data)) {
                insert('connecting_flight_details', $connecting_flight_data);
            }
            if (!empty($ticket_images)) {
                foreach ($ticket_images as $timage) {
                    $temp = array(
                        'flight_relation_id' => $flight_relation_id,
                        'case_id' => $requestdata['case_id'],
                        'flight_detail_id' => $result->flight_detail_id,
                        'document_image' => $timage,
                        'passenger_id' => $requestdata['passenger_id'],
                        'status' => 'Active',
                        'added_date' => date('Y-m-d'),
                    );
                    delete('flight_documents', 'passenger_id', $requestdata['passenger_id']);
                    insert('flight_documents', $temp);
                }
            }
            $documents = $this->api_model->getImagesByFlightRelation($flight_relation_id, $requestdata['passenger_id']);
            $connectingfligt = $this->api_model->getConnectiongFlightRelationId($flight_relation_id);
            if ($connectingfligt->isNotEmpty()) {
                $result->connecting_flight = $connectingfligt;
            } else {
                $result->connecting_flight = $connectingfligt;
            }
            if (($documents->isNotEmpty())) {
                foreach ($documents as $key => $row) {
                    $documents[$key]->document_image = url('uploads/ticket/') . '/' . $row->document_image;
                }
                $result->ticket = $documents;
                $result->passenger_id = $requestdata['passenger_id'];
            }
            return response()->json(['result' => 1, 'msg' => 'Flight details  Data', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'Something Went Wrong please try again lator', 'data' => null]);
            return false;
        }
    }

    public function additionalInformation(Request $request)
    {
        $requestdata = $request->all();
        $rules = [
            'offer_flight' => 'required',
            'case_id' => 'required',
            'flight_relation_id' => 'required',
        ];
        $flightofferd = $request->post('offer_flight');
        if ($flightofferd == 'yes') {
            $rules = [
                'offer_flight' => 'required',
                'response_of_flight' => 'required',
                'flight_delay' => 'required',
                'alternate_flight_no' => 'required',
                'alternate_flight_booking_expense' => 'required',
                'total_ammount_expense' => 'required',

            ];
        }
        $validator = Validator::make($requestdata, $rules, [
            'required' => 'This :Attribute is Required',
        ]);

        if ($validator->fails()) {
            return response()->json(['result' => 0, 'errors' => $validator->errors()->first()]);
            return false;
        }
        $flight_relation_id = $request->post('flight_relation_id');
        $insertdata = @array(
            'case_id' => $requestdata['case_id'],
            'flight_relation_id' => $requestdata['flight_relation_id'],
            'offer_flight' => $requestdata['offer_flight'],
            'response_of_flight' => $requestdata['response_of_flight'],
            'flight_delay' => $requestdata['flight_delay'],
            'alternate_flight_no' => $requestdata['alternate_flight_no'],
            'alternate_flight_booking_expense' => $requestdata['alternate_flight_booking_expense'],
            'total_ammount_expense' => $requestdata['total_ammount_expense'],
            'hotel_cost' => @$requestdata['hotel_cost'],
            'train_cost' => @$requestdata['train_cost'],
        );
        //------------------------------------Back Form Functionality---------------------------------------
        $backform = $request->post('back_form');
        // back form is passenger id
        if (!empty($backform)) {
            delete('expense_document', 'flight_relation_id', $flight_relation_id);
            $result = $this->api_model->updateAdditionalInformation($insertdata, $flight_relation_id);
        } else {
            $count = $this->api_model->getAdditinalDetailsByRelationId($flight_relation_id);
            if (empty($count)) {
                $result = $this->api_model->additionalInformation($insertdata);
            } else {
                $result = $this->api_model->getAdditinalDetailsByRelationId($flight_relation_id);
            }
        }
        if ($result) {
            // Expense Image Upload
            $expense = $request->file('expense_image');
            $expense_images = null;
            if (empty($expense)) {
                return response()->json(['result' => 0, 'errors' => 'Expense Image Is Required']);
                return false;
            } else {
                $expense_images = $this->multipleUploads($request, 'expense_image', 'expense');
                foreach ($expense_images as $timg) {
                    $expensedata = [
                        'image_name' => $timg,
                        'flight_relation_id' => $flight_relation_id,
                    ];
                    insert('expense_document', $expensedata);
                }
            }
            $expneseimages = $this->api_model->getExpenseDocumentImagesByFlightRelationId($flight_relation_id);
            if ($expneseimages->isNotEmpty()) {
                foreach ($expneseimages as $k => $v) {
                    $expneseimages[$k]->image_name = url('uploads/expense') . '/' . $v->image_name;
                }
                $result->expenseimage = $expneseimages;
            } else {
                $result->expenseimage = null;
            }
            update('passenger', 'case_id', $requestdata['case_id'], ['flight_relation_id' => $requestdata['flight_relation_id']]);
            $passengers = @$this->api_model->getPassengersByRelationId($requestdata['flight_relation_id']);
            $flightdetails = @$this->api_model->getFlightDetailsByRelationId($requestdata['flight_relation_id']);

            if ($flightdetails->isNotEmpty()) {
                $result->passenger_id = $request->post('passenger_id');
                $result->flight_details = $flightdetails;
            } else {
                $result->flight_details = null;
            }
            if ($passengers->isNotEmpty()) {
                $result->passengers = $passengers;
            } else {
                $result->passengers = null;
            }
            //  update('cases', 'case_id', $requestdata['case_id'], ['status' => 'Active']);
            return response()->json(['result' => 1, 'msg' => 'Information Details', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'Something Went Wrong please try again lator', 'data' => null]);
            return false;
        }
    }

    public function finalSubmit(Request $request)
    {
        $case_id = $request->post('case_id');
        if (empty($case_id)) {
            return response()->json(['result' => 0, 'errors' => 'Case ID Is Required']);
            return false;
        }
        update('cases', 'case_id', $case_id, ['status' => 'Active']);
        return response()->json([
            'result' => 1,
            'msg' => 'case submitted Sucessfully',
            'data' => null,
        ]);
    }

    public function getPassengersByFlightRelationID(Request $request)
    {
        $flight_relation_id = $request->post('flight_relation_id');
        $passengers = @$this->api_model->getPassengersByRelationId($flight_relation_id);
        $flightdetails = @$this->api_model->getFlightDetailsByRelationId($flight_relation_id)->first();
        if (!empty($flightdetails)) {
            $flightdetails->date_of_journey = date('d M Y', strtotime($flightdetails->date_of_journey));
            $flightdetails->arrival_date = date('d M Y', strtotime($flightdetails->arrival_date));
        }
        $final = [
            'passegers' => $passengers,
            'flight_details' => $flightdetails,
        ];
        return response()->json(['result' => 1, 'msg' => "Passenger list", 'data' => $final]);
    }

    public function getAllFormDetails(Request $request)
    {
        $flight_relation_id = $request->post('flight_relation_id');
        $passengers = @$this->api_model->getPassengersByRelationId($flight_relation_id);
        $flightdetails = @$this->api_model->getFlightDetailsByRelationId($flight_relation_id)->first();
        $connecting_flight = $this->api_model->getConnectiongFlightRelationId($flight_relation_id);
        $additional_details = $this->api_model->getAdditinalDetailsByRelationId($flight_relation_id);
        if (empty($additional_details)) {
            $additional_details = [];
        }
        if ($connecting_flight->isNotEmpty()) {
            @$flightdetails->connecting_flight_details = $connecting_flight;
           
        } else {
            @$flightdetails->connecting_flight_details = [];
        }
        if(!empty($flightdetails)){
             $flightdetails->arrival_time = date('h:i A',strtotime($flightdetails->arrival_time));
        }
        
        $images = [];
        $i = 0;
        $documents_images = $this->api_model->getImagesByFlightRelationV2($flight_relation_id);
        if ($documents_images->isNotEmpty()) {
            foreach ($documents_images as $row) {
                $row->document_image = !empty($row->document_image) ? url('/uploads/ticket/') . '/' . $row->document_image : "";
            }
        }
        $expenseimages = $this->api_model->getExpenseDocumentImagesByFlightRelationId($flight_relation_id);
        if ($expenseimages->isNotEmpty()) {
            foreach ($expenseimages as $row) {
                $row->image_name = !empty($row->image_name) ? url('/uploads/expense/') . '/' . $row->image_name : "";
            }
        }

        $finalarray = [
            'passengers' => $passengers,
            'flight_details' => $flightdetails,
            'additional_information' => $additional_details,
            'documents' => [
                'tickets' => $documents_images,
                'expense' => $expenseimages,
            ],
        ];
        return response()->json(['result' => 1, 'msg' => "Passenger list", 'data' => $finalarray]);
    }

    //---------------------------------------------------------------Update Passenger----------------------------------------------
    public function UpdatePassenger(Request $request)
    {
        $requestdata = $request->all();
        $validator = Validator::make($requestdata, [
            'passenger_id' => 'required',
            'first_name' => 'required',
            'last_name' => 'required',
            'email' => 'required|email',
            'country_code' => 'required',
            'phone' => 'required',
            'city' => 'required',
            'country' => 'required',
        ], [
            'required' => 'This :Attribute is Required',
        ]);
        if ($validator->fails()) {
            return response()->json(['result' => 0, 'errors' => $validator->errors()->first()]);
            return false;
        }
        $passenger_id = $request->post('passenger_id');
        $insertdata = array(
            'first_name' => $requestdata['first_name'],
            'last_name' => $requestdata['last_name'],
            'email' => $requestdata['email'],
            'country_code' => $requestdata['country_code'],
            'phone' => $requestdata['phone'],
            'city' => $requestdata['city'],
            'country' => $requestdata['country'],
            'date_of_birth' => str_replace('/', '-', date('Y-m-d', strtotime($requestdata['date_of_birth']))),
        );
        // back form is passenger id
        $result = $this->api_model->updatePassenger($insertdata, $passenger_id);
        if ($result) {
            return response()->json(['result' => 1, 'msg' => 'Passenger Data Updated', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'No Changes Were Found !!', 'data' => null]);
            return false;
        }
    }

    public function updateflightProcess(Request $request)
    {
        $requestdata = $request->all();
        $validator = Validator::make($requestdata, [
            'departure_from' => 'required',
            'arrival_to' => 'required',
            'date_of_journey' => 'required',
            //'flight_number' => 'required',
            'arrival_date' => 'required',
            'arrival_time' => 'required',
            'delay_days' => 'required',
            'delay_reason' => 'required',
            'passenger_id' => 'required',
        ], [
            'required' => 'This :Attribute is Required',
        ]);
        if ($validator->fails()) {
            return response()->json(['result' => 0, 'errors' => $validator->errors()->first()]);
            return false;
        }

        $passenger_id = $request->post('passenger_id');
        $flight_relation_id = @$this->api_model->getPassengersByPassengerId($passenger_id)->flight_relation_id;
        $case_id = @$this->api_model->getPassengersByPassengerId($passenger_id)->case_id;
        // connecting Flight  details
        $connecting_flight = $request->post('connecting_flight');
        $connecting_flight_data = [];
        if ($connecting_flight == 'yes') {
            $connecting_flight_no = $request->post('connecting_flight_no');
            $connecting_flight_date_of_journey = $request->post('connecting_flight_date_of_journey');
            $i = 0;
            foreach ($connecting_flight_no as $cfno) {
                $temp['connecting_flight_no'] = $cfno;
                $temp['flight_relation_id'] = $flight_relation_id;
                $temp['connecting_flight_date_of_journey'] = str_replace('/', '-', date('Y-m-d', strtotime($connecting_flight_date_of_journey[$i])));
                array_push($connecting_flight_data, $temp);
                $temp = null;
                $i++;
            }
        }

        // Ticket Image Upload
        $ticket = $request->file('ticket');
        $ticket_images = null;
        if (empty($ticket)) {
            return response()->json(['result' => 0, 'errors' => 'Ticket Image Is Required']);
            return false;
        } else {
            $ticket_images = $this->multipleUploads($request, 'ticket', 'ticket');
        }

        $updatedata = array(
            'connecting_flight' => $connecting_flight,
            'airport_departure' => $requestdata['departure_from'],
            'airport_arrival' => $requestdata['arrival_to'],
            'date_of_journey' => str_replace('/', '-', date('Y-m-d', strtotime($requestdata['date_of_journey']))),
            'flight_number' => $requestdata['flight_number'],
            'flight_name' => $requestdata['flight_name'],
            'arrival_date' => str_replace('/', '-', date('Y-m-d', strtotime($requestdata['arrival_date']))),
            'arrival_time' => str_replace('/', '-', date('Y-m-d', strtotime($requestdata['arrival_time']))),
            'notify_days' => $requestdata['delay_days'],
            'reason' => $requestdata['delay_reason'],
        );

        delete('connecting_flight_details', 'flight_relation_id', $flight_relation_id);
        $result = $this->api_model->updateflightProcess($updatedata, $flight_relation_id);
        if ($result) {
            if (!empty($connecting_flight_data)) {
                insert('connecting_flight_details', $connecting_flight_data);
            }
            if (!empty($ticket_images)) {
                foreach ($ticket_images as $timage) {
                    $temp = array(
                        'flight_relation_id' => $flight_relation_id,
                        'case_id' => $case_id,
                        'flight_detail_id' => $result->flight_detail_id,
                        'document_image' => $timage,
                        'passenger_id' => $requestdata['passenger_id'],
                        'status' => 'Active',
                        'added_date' => date('Y-m-d'),
                    );
                    delete('flight_documents', 'passenger_id', $requestdata['passenger_id']);
                    insert('flight_documents', $temp);
                }
            }
            $documents = $this->api_model->getImagesByFlightRelation($flight_relation_id, $requestdata['passenger_id']);

            $connectingfligt = $this->api_model->getConnectiongFlightRelationId($flight_relation_id);
            if ($connectingfligt->isNotEmpty()) {
                $result->connecting_flight = $connectingfligt;
            } else {
                $result->connecting_flight = $connectingfligt;
            }
            if (($documents->isNotEmpty())) {
                foreach ($documents as $key => $row) {
                    $documents[$key]->document_image = url('uploads/ticket/') . '/' . $row->document_image;
                }
                $result->ticket = $documents;
                $result->passenger_id = $requestdata['passenger_id'];
            }
            return response()->json(['result' => 1, 'msg' => 'Flight details  Data Updated Successfully', 'data' => $result]);
            return false;
        } else {

            return response()->json(['result' => -1, 'msg' => 'Something Went Wrong please try again lator', 'data' => null]);
            return false;
        }
    }

    public function updateadditionalInformation(Request $request)
    {
        $requestdata = $request->all();
        $rules = [
            'passenger_id' => 'required',
            'offer_flight' => 'required',
            'passenger_id' => 'required',
        ];
        $flightofferd = $request->post('offer_flight');
        if ($flightofferd == 'yes') {
            $rules = [
                'offer_flight' => 'required',
                'response_of_flight' => 'required',
                'flight_delay' => 'required',
                'alternate_flight_no' => 'required',
                'alternate_flight_booking_expense' => 'required',
                'total_ammount_expense' => 'required',
            ];
        }
        $validator = Validator::make($requestdata, $rules, [
            'required' => 'This :Attribute is Required',
        ]);

        if ($validator->fails()) {
            return response()->json(['result' => 0, 'errors' => $validator->errors()->first()]);
            return false;
        }
        $passenger_id = $request->post('passenger_id');
        $flight_relation_id = @$this->api_model->getPassengersByPassengerId($passenger_id)->flight_relation_id;
        $case_id = @$this->api_model->getPassengersByPassengerId($passenger_id)->case_id;
        // connecting Flight  details
        $updatedata = @array(
            'offer_flight' => $requestdata['offer_flight'],
            'response_of_flight' => $requestdata['response_of_flight'],
            'flight_delay' => $requestdata['flight_delay'],
            'alternate_flight_no' => $requestdata['alternate_flight_no'],
            'alternate_flight_booking_expense' => $requestdata['alternate_flight_booking_expense'],
            'total_ammount_expense' => $requestdata['total_ammount_expense'],
            'hotel_cost' => $requestdata['hotel_cost'],
            'train_cost' => $requestdata['train_cost'],
        );

        $result = $this->api_model->updateAdditionalInformation($updatedata, $flight_relation_id);
        if ($result) {
            // Expense Image Upload
            $expense = $request->file('expense_image');
            $expense_images = null;
            if (empty($expense)) {
            } else {
                $this->api_model->deleteExpenseImage($flight_relation_id);
                $expense_images = $this->multipleUploads($request, 'expense_image', 'expense');
                foreach ($expense_images as $timg) {
                    $expensedata = [
                        'image_name' => $timg,
                        'flight_relation_id' => $flight_relation_id,
                    ];
                    insert('expense_document', $expensedata);
                }
            }
            $expneseimages = $this->api_model->getExpenseDocumentImagesByFlightRelationId($flight_relation_id);
            if ($expneseimages->isNotEmpty()) {
                foreach ($expneseimages as $k => $v) {
                    $expneseimages[$k]->image_name = url('uploads/expense') . '/' . $v->image_name;
                }
                $result->expenseimage = $expneseimages;
            } else {
                $result->expenseimage = null;
            }

            $passengers = @$this->api_model->getPassengersByRelationId($requestdata['flight_relation_id']);
            $flightdetails = @$this->api_model->getFlightDetailsByRelationId($requestdata['flight_relation_id']);

            if ($flightdetails->isNotEmpty()) {
                $result->passenger_id = $request->post('passenger_id');
                $result->flight_details = $flightdetails;
            } else {
                $result->flight_details = null;
            }
            if ($passengers->isNotEmpty()) {
                $result->passengers = $passengers;
            } else {
                $result->passengers = null;
            }

            return response()->json(['result' => 1, 'msg' => 'Information Details updates', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'Something Went Wrong please try again lator', 'data' => null]);
            return false;
        }
    }

    //==============================================================================Flight API=======================================================
    public function getCountry(Request $request)
    {
        $result = $this->api_model->getCountry();
        if ($result) {
            return response()->json(['result' => 1, 'msg' => 'Country List', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'No Country Data Found!!', 'data' => null]);
            return false;
        }
    }

    public function getCity(Request $request)
    {
        $countryiso = $request->post('contryisocode');
        if (empty($countryiso)) {
            return response()->json(['result' => -1, 'msg' => 'No City Available!!', 'data' => null]);
            return false;
        }
        $result = $this->api_model->getCity($countryiso);
        if ($result->isNotEmpty()) {
            return response()->json(['result' => 1, 'msg' => 'City List', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'No City Found!!', 'data' => null]);
            return false;
        }
    }

    public function getAirport(Request $request)
    {
        $keyword = $request->post('keyword');
        $orgin = $request->post('orgin');
        $result = $this->api_model->getAirport($keyword, $orgin);
        if ($result) {
            return response()->json(['result' => 1, 'msg' => 'Airport List', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'No Airport Data Found!!', 'data' => null]);
            return false;
        }
    }

    public function getAirline(Request $request)
    {
        $keyword = $request->get('keyword');
        $result = $this->api_model->getAirline($keyword);
        if ($result) {
            return response()->json(['result' => 1, 'msg' => 'Airlines data found ', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'No Airline  Data Found!!', 'data' => null]);
            return false;
        }
    }

    public function caseHistory(Request $request)
    {
        $user_token = $request->header('token');
        $user_data = $this->api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            return response()->json(['result' => -2, 'msg' => 'User already logged in on a different device'], 401);
            return false;
        }
        if ($user_data->status == 'Inactive') {
            header('HTTP/1.1 402 User Account Is Inactive.', true, 402);
            return response()->json(['result' => -2, 'msg' => 'Your account has been inactive by admin.'], 401);
            return false;
        }
        $user_id = $user_data->user_id;
        $result = $this->api_model->caseHistory($user_id);
        if ($result->isNotEmpty()) {
            if ($result->isNotEmpty()) {
                foreach ($result as $row) {
                    $row->refundamt = @$this->api_model->getPaymentBycaseID($row->case_id)->first()->refunded_amount;
                    $row->date_update = @convertToHoursMinsSec($row->updated_at);
                }
            }
            return response()->json(['result' => 1, 'msg' => 'Case History data found ', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'No Case History  Data Found!!', 'data' => null]);
            return false;
        }
    }

    public function caseHistoryDetails(Request $request)
    {
        $case_id = $request->post('case_id');
        if (empty($case_id)) {
            return response()->json(['result' => 0, 'msg' => 'Case ID is Required ']);
        }
        $result = $this->api_model->caseHistoryDetails($case_id);
        if ($result) {
            if ($result) {
                $result->refundamt = @$this->api_model->getPaymentBycaseID($result->case_id)->first()->refunded_amount;
                $result->rating = @ceil($this->api_model->getRatingsByCaseId($result->case_id));
                $result->completion_date = !validateDate(changeDateFormat($result->completion_date)) ? @changeDateFormat($result->completion_date) : null;
                $result->submission_date = !validateDate(changeDateFormat($result->submission_date)) ? @changeDateFormat($result->submission_date) : null;
                $result->date_update = @convertToHoursMinsSec($result->updated_at);
                //$result->submission_date = !validateDate(changeDateFormat($result->submission_date)) ? @changeDateFormat($result->submission_date) : null;
            }
            return response()->json(['result' => 1, 'msg' => 'Case History Details found ', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'No Case History  Data Found!!', 'data' => null]);
            return false;
        }
    }

    public function rating(Request $request)
    {
        $user_token = $request->header('token');
        $user_data = $this->api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            return response()->json(['result' => -2, 'msg' => 'User already logged in on a different device'], 401);
            return false;
        }
        $user_id = $user_data->user_id;
        $case_id = $request->post('case_id');
        $ratings = $request->post('rating');
        if (empty($case_id)) {
            return response()->json(['result' => 0, 'msg' => 'Case ID is Required ']);
        }
        if (empty($ratings)) {
            return response()->json(['result' => 0, 'msg' => 'Rating is Required ']);
        }

        $insertdata = array(
            'case_id' => $case_id,
            'rating' => $ratings,
            'user_id' => $user_id,
        );

        $result = insert('case_ratings', $insertdata);
        if ($result) {
            return response()->json(['result' => 1, 'msg' => 'You Rated the case ', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'Opps Something Went Wrong!!', 'data' => null]);
            return false;
        }
    }

    public function getNotifications(Request $request)
    {
        $user_token = $request->header('token');
        $user_data = $this->api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            return response()->json(['result' => -2, 'msg' => 'User already logged in on a different device'], 401);
            return false;
        }
        if ($user_data->status == 'Inactive') {
            header('HTTP/1.1 402 User Account Is Inactive.', true, 402);
            return response()->json(['result' => -2, 'msg' => 'Your account has been inactive by admin.'], 401);
            return false;
        }
        $user_id = $user_data->user_id;
        $result = $this->api_model->getNotification($user_id);
        if ($result) {
            $finalarray = [];
            foreach ($result as $row) {
                $case_details = $this->api_model->getCaseByCaseid($row->case_id);
                $agreement = false;
                if (($case_details->power_of_attorney_accepted == 1) && ($case_details->payment_aggrement_accepted == 1) && ($row->type == 'agreement')) {
                    $agreement = true;
                }
                $row->time = @convertToHoursMinsSec($row->notification_date);
                $row->notification_date = date('d M y', strtotime($row->notification_date));
                if ($agreement == false) {
                    $finalarray[] = $row;
                }

            }
            return response()->json(['result' => 1, 'msg' => 'Notification List ', 'data' => $finalarray]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'Opps Something Went Wrong!!', 'data' => null]);
            return false;
        }
    }

    public function documentUpload(Request $request)
    {
        $user_token = $request->header('token');
        $user_data = $this->api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            return response()->json(['result' => -2, 'msg' => 'User already logged in on a different device'], 401);
            return false;
        }
        $user_id = $user_data->user_id;
        $case_id = $request->post('case_id');
        $case_details = $this->api_model->getCaseByCaseid($case_id);
        if (!empty($case_details)) {
            $passengerlist = $this->api_model->getPassengersByRelationId($case_details->flight_relation_id);
        } else {
            $passengerlist = $this->api_model->getPassengersByRelationId(0);
        }
        $key = $request->post('key');
        if (empty($case_id)) {
            return response()->json(['result' => 0, 'msg' => 'case id is required']);
            return false;
        }
        if (empty($key)) {
            return response()->json(['result' => 0, 'msg' => 'Key id is required']);
            return false;
        }
        if ($key == 'passport') {
            $totalpassenger = $passengerlist->count();
            $passengerdata = $this->api_model->getPassportByCaseID($case_id);
            if ($passengerdata->isNotEmpty()) {
                @$allpassport = $request->post('passport_number');
                $i = 0;
                foreach ($allpassport as $pass) {
                    if (empty($pass)) {
                        return response()->json(['result' => 0, 'msg' => 'passport number of ' . @$passengerlist[$i]->first_name . ' is required']);
                        return false;
                    }
                    $updatepassport = [
                        'passport_number' => @$allpassport[$i],
                    ];
                    update('passenger_passport', 'passenger_passport_id', $passengerdata[$i]->passenger_passport_id, $updatepassport);
                    $i++;
                }
            } else {
                if ($passengerlist->isNotEmpty()) {
                    @$allpassport = $request->post('passport_number');
                    $i = 0;
                    foreach ($allpassport as $pass) {
                        if (empty($pass)) {
                            return response()->json(['result' => 0, 'msg' => 'passport number of ' . @$passengerlist[$i]->first_name . ' is required']);
                            return false;
                        }

                        $temppassport = [
                            'user_id' => $user_id,
                            'case_id' => $case_id,
                            'passenger_id' => @$passengerlist[$i]->passenger_id,
                            'passport_number' => @$allpassport[$i],
                        ];
                        insert('passenger_passport', $temppassport);
                        $i++;
                    }
                }
            }
            $passengerdata = $this->api_model->getPassportByCaseID($case_id);
            return response()->json(['result' => 1, 'msg' => 'passport data inserted!!', 'data' => $passengerdata]);
            return false;
        } elseif ($key == 'accountdetails') {
            $accountdetails = $this->api_model->getAccountDetailsByUserId($user_id);
            $bank_holder_name = $request->post('bank_holder_name');
            $ibn = $request->post('ibn');
            $bank_name = $request->post('bank_name');
            $bic_swift = $request->post('bic_swift');
            if (empty($bank_holder_name)) {
                return response()->json(['result' => 0, 'msg' => 'Bank Holder Name is required']);
                return false;
            }
            if (empty($ibn)) {
                return response()->json(['result' => 0, 'msg' => 'IBN  is required']);
                return false;
            }
            if (empty($bank_name)) {
                return response()->json(['result' => 0, 'msg' => 'Bank  Name is required']);
                return false;
            }
            if (empty($bic_swift)) {
                return response()->json(['result' => 0, 'msg' => 'BiC/Swift is required']);
                return false;
            }

            if (!empty($accountdetails)) {
                $updatedata = array(
                    'user_id' => $user_id,
                    'case_id' => $case_id,
                    'account_holder_name' => $bank_holder_name,
                    'iban_number' => $ibn,
                    'bank_name' => $bank_name,
                    'bic_swift' => $bic_swift,
                );
                update('passenger_account_details', 'account_details_id', $accountdetails->account_details_id, $updatedata);
            } else {
                $insertdata = array(
                    'user_id' => $user_id,
                    'case_id' => $case_id,
                    'account_holder_name' => $bank_holder_name,
                    'iban_number' => $ibn,
                    'bank_name' => $bank_name,
                    'bic_swift' => $bic_swift,
                );
                insert('passenger_account_details', $insertdata);
            }
            $accountdata = $this->api_model->getAccountDetailsByCaseId($case_id);
            return response()->json(['result' => 1, 'msg' => 'passport data inserted!!', 'data' => $accountdata]);
            return false;
        }
        if ($key == 'documents') {
            $passport = $request->file('passport_document');
            $personalid = $request->file('personal_document');
            // if (empty($passport[0])) {
            //     return response()->json(['result' => 0, 'msg' => 'passport document  is required']);
            //     return false;
            // }
            // if (empty($personalid[0])) {
            //     return response()->json(['result' => 0, 'msg' => 'personal id is required']);
            //     return false;
            // }
            //delete('passenger_documents', 'case_id', $case_id);
            $passport_images = $this->multipleUploads($request, 'passport_document', 'passenger_documents');
            $personal_images = $this->multipleUploads($request, 'personal_document', 'passenger_documents');
            $i = 0;
            if ($request->hasfile('passport_document')) {
                foreach ($passport as $p) {
                    $temppassport = [
                        'user_id' => $user_id,
                        'case_id' => $case_id,
                        'document_type' => 'passport',
                        'document_url' => @$passport_images[$i],
                    ];
                    insert('passenger_documents', $temppassport);
                    $i++;
                }
            }
            $j = 0;
            if ($request->hasfile('personal_document')) {
                foreach ($personalid as $p) {
                    $temppassport1 = [
                        'user_id' => $user_id,
                        'case_id' => $case_id,
                        // 'document_type' => 'personal_id',
                        'document_type' => 'personal_id',
                        'document_url' => @$personal_images[$j],
                    ];
                    insert('passenger_documents', $temppassport1);
                    $j++;
                }
            }

            $documents = $this->api_model->getPassengerDocumentsByCaseId($case_id);

            if (($documents->isNotEmpty())) {
                foreach ($documents as $row) {
                    $row->document_url = url('uploads/passenger_documents/') . '/' . @$row->document_url;
                }
            }
            return response()->json(['result' => 1, 'msg' => 'Files Uploaded successfully !!', 'data' => @$documents]);
            return false;
        } elseif ($key == 'final') {
            $noficationid = $request->post('notification_id');
            // $passengerdata = $this->api_model->getPassportByCaseID($case_id);
            // if($passengerdata->isEmpty()){
            //     return response()->json(['result' => -1, 'msg' => 'Passport data is required!!']);
            // }
            // $documents = $this->api_model->getPassengerDocumentsByCaseId($case_id);
            // if($documents->isEmpty()){
            //     return response()->json(['result' => -1, 'msg' => 'documents data is required!!']);
            //     return false;
            // }
            // $accountdetails = $this->api_model->getAccountDetailsByUserId($user_id);
            // if(empty($accountdetails)){
            //     return response()->json(['result' => -1, 'msg' => 'Account Details data is required!!']);
            //     return false;
            // }
            update('notification', 'notification_id', $noficationid, ['status' => 'Inactive']);
            return response()->json(['result' => 1, 'msg' => 'Final Data Submitted!!', 'data' => []]);
            return false;
        }
    }

    public function getNotificationDocumentDetails(Request $request)
    {
        $user_token = $request->header('token');
        $user_data = $this->api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            return response()->json(['result' => -2, 'msg' => 'User already logged in on a different device'], 401);
            return false;
        }
        $user_id = $user_data->user_id;
        $key = $request->post('key');
        $case_id = $request->post('case_id');
        $notification_id = $request->post('notification_id');
        if ($key == 'passport') {

            //$passportdata=$this->api_model->getPassportByUserID($user_id);
            $passengerdata = $this->api_model->getPassengerByCaseID($case_id);
            return response()->json(['result' => 1, 'msg' => 'passport data Details!!', 'data' => $passengerdata]);
            return false;
        }
        if ($key == 'accountdetails') {
            $accountdata = @$this->api_model->getAccountDetailsByUserId($user_id);
            return response()->json(['result' => 1, 'msg' => 'passport data details!!', 'data' => $accountdata]);
            return false;
        }
        if ($key == 'documents') {

            $data['passport'] = $this->api_model->getPassengerDocumentsByUserID($user_id, 'passport', $case_id);
            if ($data['passport']->isNotEmpty()) {
                foreach ($data['passport'] as $p) {
                    $p->document_url = url('uploads/passenger_documents') . '/' . $p->document_url;
                }
            }
            $data['personal_id'] = $this->api_model->getPassengerDocumentsByUserID($user_id, 'personal_id', $case_id);
            if ($data['personal_id']->isNotEmpty()) {
                foreach ($data['personal_id'] as $p) {
                    $p->document_url = url('uploads/passenger_documents') . '/' . $p->document_url;
                }
            }
            return response()->json(['result' => 1, 'msg' => 'Document data details!!', 'data' => $data]);
            return false;
        }

    }

    public function caseStatus(Request $request)
    {
        $user_token = $request->header('token');
        $user_data = $this->api_model->getUserByToken($user_token);
        if (empty($user_data)) {
            header('HTTP/1.1 402 User already logged in on a different device', true, 402);
            return response()->json(['result' => -2, 'msg' => 'User already logged in on a different device'], 401);
            return false;
        }
        if ($user_data->status == 'Inactive') {
            header('HTTP/1.1 402 User Account Is Inactive.', true, 402);
            return response()->json(['result' => -2, 'msg' => 'Your account has been inactive by admin.'], 401);
            return false;
        }
        $user_id = $user_data->user_id;
        $result = $this->api_model->getAllcaseUserIDForCase($user_id);

        if ($result->isNotEmpty()) {
            foreach ($result as $row) {
                $row->date_update = @convertToHoursMinsSec($row->updated_at);
                $row->case_progress_status = $this->api_model->caseStatusByCaseId($row->case_id);
                $row->case_type = ucwords(str_replace('_', ' ', $row->case_type));
            }
        }

        if ($result) {
            return response()->json(['result' => 1, 'msg' => 'Case Status ', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'Opps Something Went Wrong!!', 'data' => null]);
            return false;
        }
    }

    public function powerofAttorneyOrPaymentAggreementUpdate(Request $request)
    {
        $case_id = $request->post('case_id');
        $type = $request->post('type');
        if (empty($case_id)) {
            return response()->json(['result' => 0, 'msg' => 'Case Id Is Required!!']);
            return false;
        }
        if (empty($type)) {
            return response()->json(['result' => 0, 'msg' => 'type Is Required!!']);
            return false;
        }
        $casedata = $this->api_model->getCaseByCaseid($case_id);
        if ($type == 'power_of_attorney') {
            $temp = ['power_of_attorney_accepted' => 1];
            $msg = "you accepeted the power of attroney";
            $statusmsg = 'power of attroney accepted';
            if (!empty($casedata)) {
                if ($casedata->power_of_attorney_accepted == 1) {
                    return response()->json(['result' => -1, 'msg' => 'You Already Accept this!!']);
                    return false;
                }
            }
            $result = $this->api_model->updatepowerofAttorneyOrPaymentAggreementUpdate($case_id, $temp, $msg, $statusmsg);
        } else {
            $temp = ['payment_aggrement_accepted' => 1];
            $msg = "you accepeted the Payement Aggrement";
            $statusmsg = 'Payement Agrrement accepted';
            if (!empty($casedata)) {
                if ($casedata->payment_aggrement_accepted == 1) {
                    return response()->json(['result' => -1, 'msg' => 'You Already Accept this!!']);
                    return false;
                }
            }
            $result = $this->api_model->updatepowerofAttorneyOrPaymentAggreementUpdate($case_id, $temp, $msg, $statusmsg);
        }

        if ($result) {
            return response()->json(['result' => 1, 'msg' => $type . ' is Accepted', 'data' => $result]);
            return false;
        } else {
            return response()->json(['result' => -1, 'msg' => 'Opps Something Went Wrong!!', 'data' => null]);
            return false;
        }
    }

    //----------------------------------------------Get Details API-------------------------------
    public function getPassengerByPassengerId(Request $request)
    {
        $passenger_id = $request->post('passenger_id');
        if (empty($passenger_id)) {
            return response()->json(['result' => 0, 'msg' => 'Passenger id is Required !!']);
        }
        $result = $this->api_model->getPassengerByPassengerId($passenger_id);
        if ($result) {
            return response()->json(['result' => 1, 'msg' => 'Passenegr Details Fetched', 'data' => $result]);
        } else {

            return response()->json(['result' => 1, 'msg' => 'Passenegr Details Fetched', 'data' => null]);
        }
    }
    public function getFlightProcess(Request $request)
    {
        $flight_relation_id = $request->post('flight_relation_id');
        if (empty($flight_relation_id)) {
            return response()->json(['result' => 0, 'msg' => 'Flight Relation id is Required !!']);
        }
        $result = $this->api_model->getFlightDetailsByRelationId($flight_relation_id)->first();
        if ($result) {
            $documents_images = $this->api_model->getImagesByFlightRelationV2($flight_relation_id);
            if ($documents_images->isNotEmpty()) {
                foreach ($documents_images as $row) {
                    $row->document_image = !empty($row->document_image) ? url('/uploads/ticket/') . '/' . $row->document_image : "";
                }
            }
            $result->document_images = $documents_images;
            $connecting_flight = $this->api_model->getConnectiongFlightRelationId($flight_relation_id);
            if ($connecting_flight->isNotEmpty()) {
                $result->connecting_flight = $connecting_flight;
            } else {
                $result->connecting_flight = null;
            }
            return response()->json(['result' => 1, 'msg' => 'flight  Details Fetched', 'data' => $result]);
        } else {
            return response()->json(['result' => 1, 'msg' => 'Flight Details Fetched', 'data' => null]);
        }
    }

    public function getAdditionalDetails(Request $request)
    {
        $flight_relation_id = $request->post('flight_relation_id');
        $result = $this->api_model->getAdditinalDetailsByRelationId($flight_relation_id);
        if ($result) {
            $expenseimages = $this->api_model->getExpenseDocumentImagesByFlightRelationId($flight_relation_id);
            if ($expenseimages->isNotEmpty()) {
                foreach ($expenseimages as $row) {
                    $row->image_name = !empty($row->image_name) ? url('/uploads/expense/') . '/' . $row->image_name : "";
                }
            }
            $result->expense_image = @$expenseimages;
            return response()->json(['result' => 1, 'msg' => 'flight  Additional Details Fetched', 'data' => $result]);
        } else {
            return response()->json(['result' => 1, 'msg' => 'Flight Details Fetched', 'data' => null]);
        }
    }

    public function deleteDocument(Request $request)
    {
        $document_id = $request->post('document_id');
        $result = delete('passenger_documents', 'passenger_documents_id', $document_id);
        if ($result) {
            return response()->json(['result' => 1, 'msg' => 'File Deleted', 'data' => []]);
        } else {
            return response()->json(['result' => 1, 'msg' => 'Something Went Wrong', 'data' => null]);
        }
    }
    
    public function caseDetails(Request $request){
        $case_id = $request->post('case_id');
        $result =$this->api_model->getCaseByCaseid($case_id);
        if ($result) {
            return response()->json(['result' => 1, 'msg' => 'Case Details', 'data' => $result]);
        } else {
            return response()->json(['result' => 1, 'msg' => 'Something Went Wrong', 'data' => null]);
        }
        
    }

}
