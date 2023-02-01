<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;

class ApiModel extends Model
{
    use HasFactory;

    public function genrateToken()
    {
        $token = openssl_random_pseudo_bytes(16);
        $token = bin2hex($token);
        return $token;
    }

    public function doRegister($data, $device_type)
    {
        DB::beginTransaction();
        try {
            DB::table('users')->insert($data);
            $id = DB::getPdo()->lastInsertId();
            if (!empty($id)) {
                $token = array(
                    'user_token' => $this->genrateToken(),
                    'user_id' => $id,
                    'device_type' => $device_type,
                );
                DB::table('users_authentication')->insert($token);
            }
            DB::commit();
            return $id;
        } catch (\Exception $e) {

            DB::rollback();
            return false;
        }
    }

    public function getUserByID($id)
    {
        return DB::table('users')
            ->select('users.user_id', \DB::raw("substr(users.name, 1, 1) as firstletter"), 'users.name', 'users.email', 'users.country_code', 'users.is_verified', 'users.mobile', 'users.source', 'users.otp', 'users.terms', 'users.privacy', 'users.status', 'users_authentication.user_token', 'users_authentication.firebase_token')
            ->join('users_authentication', 'users.user_id', '=', 'users_authentication.user_id')
            ->where('users.user_id', $id)->get()->first();
    }

    public function getUserByToken($token)
    {
        return DB::table('users')
            ->select('users.user_id', \DB::raw("substr(users.name, 1, 1) as firstletter"), 'users.name', 'users.email', 'users.country_code', 'users.is_verified', 'users.mobile', 'users.source', 'users.otp', 'users.terms', 'users.privacy', 'users.status', 'users_authentication.user_token', 'users_authentication.firebase_token')
            ->join('users_authentication', 'users.user_id', '=', 'users_authentication.user_id')
            ->where('users_authentication.user_token', $token)->get()->first();
    }

    public function getUserByEmail($email)
    {
        return DB::table('users')
            ->select('users.user_id', \DB::raw("substr(users.name, 1, 1) as firstletter"), 'users.name', 'users.email', 'users.country_code', 'users.is_verified', 'users.mobile', 'users.source', 'users.otp', 'users.terms', 'users.privacy', 'users.status', 'users_authentication.user_token', 'users_authentication.firebase_token')
            ->join('users_authentication', 'users.user_id', '=', 'users_authentication.user_id')
            ->where('users.email', $email)->where('users.source', 'self')->get()->first();
    }

    public function sendOtp($otp, $user_id)
    {
        DB::table('users')->where('user_id', $user_id)->update(['otp' => $otp]);
        return true;
    }

    public function verifyOtp($otp, $user_id)
    {
        return DB::table('users')->where('user_id', $user_id)->where('otp', $otp)->where('status', 'Active')->get()->first();
    }

    public function updateVerifyStatus($user_id)
    {
        return DB::table('users')->where('user_id', $user_id)->update(['is_verified' => 'yes']);
    }

    public function resetPassword($user_id, $newpassword)
    {
        return DB::table('users')->where('user_id', $user_id)->update(['password' => hash('sha256', $newpassword)]);
    }

    public function checkoldpassword($old_pass, $user_id)
    {
        return DB::table('users')->where('password', hash('sha256', $old_pass))->where('user_id', $user_id)->get()->first();
    }

    // change password
    public function changePassword($user_id, $old_pass, $new_pass)
    {
        $old_p = hash('sha256', $old_pass);
        $data = DB::table('users')->where(
            ['user_id' => $user_id],
            ['password' => $old_p]
        )->get()->first();
        if (!empty($data)) {
            DB::table('users')->where('user_id', $user_id)->update(['password' => hash('sha256', $new_pass)]);
            return true;
        } else {
            return false;
        }
    }

    public function doLogin($email, $password)
    {
        return DB::table('users')->where('email' ,$email)->where('password',$password)->get()->first();
    }

    public function checkUserExistWithSocialId($social_id)
    {
        return DB::table('users')->where('social_id', $social_id)->get()->first();
    }
    public function checkSocialUserData($email, $social_type)
    {
        return DB::table('users')
            ->select('users.user_id', 'users.name', 'users.email', 'users.country_code', 'users.is_verified', 'users.mobile', 'users.source', 'users.otp', 'users.terms', 'users.privacy', 'users.status', 'users_authentication.user_token', 'users_authentication.firebase_token')
            ->join('users_authentication', 'users.user_id', '=', 'users_authentication.user_id')
            ->where('users.email', $email)->where('users.status', '!=', 'Deleted')->where('users.source', $social_type)->get()->first();
    }

    public function insertSocialUserData($social_type, $email, $social_id, $name, $device_type = 'android')
    {
        $data = array(
            'email' => $email,
            'name' => $name,
            'source' => $social_type,
            'social_id' => $social_id,
            'is_verified' => 'yes',
        );
        DB::beginTransaction();
        try {
            DB::table('users')->insert($data);
            $id = DB::getPdo()->lastInsertId();
            if (!empty($id)) {
                $token = array(
                    'user_token' => $this->genrateToken(),
                    'user_id' => $id,
                    'device_type' => $device_type,
                );
                DB::table('users_authentication')->insert($token);
            }
            DB::commit();
            return $id;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function updateSocialUserData($social_type, $email, $social_id, $user_id, $name, $device_type = 'android')
    {
        $data = array(
            'source' => $social_type,
            'name' => $name,
            'social_id' => $social_id,
            'status' => 'Active',
            'is_verified' => 'yes',
        );

        DB::beginTransaction();
        try {
            DB::table('users')->where('email', $email)->update($data);
            $token = array(
                'user_token' => $this->genrateToken(),
                'device_type' => $device_type,
            );
            DB::table('users_authentication')->where('user_id', $user_id)->update($token);

            DB::commit();
            return true;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getSettingPage($page)
    {
        if ($page != 'help') {
            return DB::table('setting')->Where('type', $page)->get()->first();
        } else {
            return DB::table('contact_details')->get()->first();
        }
    }

    public function getHandBook()
    {
        return DB::table('handbook')->get()->first();
    }

    // firebasetoken releted queries
    public function checkfirebaseToken($token, $user_id)
    {
        return DB::table('users_authentication')->where('firebase_token',$token)->where('user_id', $user_id)->get()->first();
    }
    public function updatefirebaseToken($token, $user_id, $device_type)
    {
        DB::table('users_authentication')->where('user_id',$user_id)->update(['firebase_token' => $token, 'device_type' => $device_type]);
        return true;
    }

    public function deleteFirebaseToken($user_id)
    {
        DB::table('users_authentication')->where('user_id' , $user_id)->update(['firebase_token' => null]);
        return true;
    }
    public function updateToken($user_id, $token)
    {
        DB::table('users_authentication')->where('user_id' , $user_id)->update(['user_token' => $token]);
        return true;
    }
    public function insertToken($data)
    {
        DB::table('users_authentication')->insert($data);
        return true;
    }
    //-------------------------------------------------------Flight Releted apis-------------------------------------------------------------

    public function caseType($data)
    {
        try {
            DB::beginTransaction();
            DB::table('cases')->insert($data);
            $id = DB::getPdo()->lastInsertId();
            $data = DB::table('cases')->where('case_id', $id)->get()->first();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function addPassenger($data)
    {
        try {
            DB::beginTransaction();
            DB::table('passenger')->insert($data);
            $id = DB::getPdo()->lastInsertId();
            $data = DB::table('passenger')->where('passenger_id', $id)->get()->first();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function flightProcess($data)
    {
        try {
            DB::beginTransaction();
            DB::table('flight_details')->insert($data);
            $id = DB::getPdo()->lastInsertId();
            $data = DB::table('flight_details')->where('flight_detail_id', $id)->get()->first();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function additionalInformation($data)
    {
        try {
            DB::beginTransaction();
            DB::table('additional_information')->insert($data);
            $id = DB::getPdo()->lastInsertId();
            $data = DB::table('additional_information')->where('information_id', $id)->get()->first();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getImagesByFlightRelation($flight_relation_id, $pid)
    {
        try {
            DB::beginTransaction();
            $data = DB::table('flight_documents')->addSelect('document_image', 'passenger_id')->where('flight_relation_id', $flight_relation_id)->where('status', 'Active')->where('passenger_id', $pid)->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }
    
    public function getImagesByFlightRelationV2($flight_relation_id)
    {
        try {
            DB::beginTransaction();
            $data = DB::table('flight_documents')->addSelect('document_image', 'passenger_id')->where('flight_relation_id', $flight_relation_id)->where('status', 'Active')->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getPassengersByRelationId($flight_relation_id)
    {
        try {
            DB::beginTransaction();
            $data = DB::table('passenger')->where('flight_relation_id', $flight_relation_id)->where('status', 'Active')->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }
    public function getPassengersByPassengerId($passenger_id)
    {
        try {
            DB::beginTransaction();
            $data = DB::table('passenger')->where('passenger_id', $passenger_id)->where('status', 'Active')->get()->first();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }
    public function getConnectiongFlightRelationId($flight_relation_id)
    {
        try {
            DB::beginTransaction();
            $data = DB::table('connecting_flight_details')->where('flight_relation_id', $flight_relation_id)->where('status', 'Active')->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getFlightDetailsByRelationId($flight_relation_id)
    {
        try {
            DB::beginTransaction();
            $data = DB::table('flight_details')->where('flight_relation_id', $flight_relation_id)->where('status', 'Active')->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }
    public function getAdditinalDetailsByRelationId($flight_relation_id)
    {
        try {
            DB::beginTransaction();
            $data = DB::table('additional_information')->where('flight_relation_id', $flight_relation_id)->where('status', 'Active')->get()->first();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function updatePassenger($data, $passenger_id)
    {
        try {
            DB::beginTransaction();
            DB::table('passenger')->where('passenger_id', $passenger_id)->update($data);
            $data = DB::table('passenger')->where('passenger_id', $passenger_id)->get()->first();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function updateflightProcess($data, $flight_relation_id)
    {
        try {
            DB::beginTransaction();
            DB::table('flight_details')->where('flight_relation_id', $flight_relation_id)->update($data);
            $data = DB::table('flight_details')->where('flight_relation_id', $flight_relation_id)->get()->first();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function updateAdditionalInformation($data, $flight_relation_id)
    {
        try {
            DB::beginTransaction();
            DB::table('additional_information')->where('flight_relation_id', $flight_relation_id)->update($data);
            $data = DB::table('additional_information')->where('flight_relation_id', $flight_relation_id)->get()->first();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getCountry()
    {
        try {
            DB::beginTransaction();
            $data = DB::table('country')->addSelect('countryId', 'nameCountry', 'codeIso2Country')->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }

    }

    public function getCity($country_iso)
    {
        try {
            DB::beginTransaction();
            $data = DB::table('city')->addSelect('cityId', 'nameCity')->where('codeIso2Country', $country_iso)->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }

    }

    public function getAirport($keyword,$orgin=null)
    {
        try {
            DB::beginTransaction();
            $data = DB::table('airport')->addSelect('airportId', 'nameAirport', 'nameCountry', 'codeIso2Country');
            if (!empty($keyword)) {;
                $data->whereRaw('(REPLACE(nameAirport," ","")) LIKE "%' . str_replace(' ', '%', $keyword) . '%"');
            }
            if($orgin == true){
                 $data = $data->where('codeIso2Country','DE')->limit(50)->get();
            }else{
                 $data = $data->limit(50)->get();
            }
           
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }

    }

    public function getAirline($keyword)
    {
        try {
            DB::beginTransaction();
            $data = DB::table('airlines')->addSelect('airlineId',DB::raw("CONCAT(nameAirline,' ',nameCountry) AS nameAirline"), 'nameCountry', 'codeIso2Country');
            if (!empty($keyword)) {
                $data->whereRaw('(REPLACE(nameAirline," ","")) LIKE "%' . str_replace(' ', '%', $keyword) . '%"');
            }
            $data = $data->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function caseHistory($user_id)
    {
        try {
            DB::beginTransaction();
            $data = DB::table('cases')->addSelect('cases.case_id', 'cases.case_refrence_no', 'cases.case_status', 'cases.updated_at', 'flight_details.flight_name', 'flight_details.flight_number')
                ->leftJoin('flight_details', 'cases.flight_relation_id', '=', 'flight_details.flight_relation_id')->where('cases.user_id','=',$user_id);
            $data->whereIn('cases.case_status', ['dismissed', 'completed']);
            $data = $data->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getPaymentBycaseID($case_id){
        try {
            DB::beginTransaction();
            $data = DB::table('payments')->addSelect('*');
            $data->where('case_id',$case_id);
            $data = $data->orderBydesc('payment_id')->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function caseHistoryDetails($case_id){
        try {
            DB::beginTransaction();
            $data = DB::table('cases')->addSelect('cases.case_id', 'cases.case_refrence_no', 'cases.case_status', 'cases.submission_date','cases.completion_date','cases.updated_at', 'flight_details.flight_name', 'flight_details.flight_number')
                ->leftJoin('flight_details', 'cases.flight_relation_id', '=', 'flight_details.flight_relation_id');
            $data->where('cases.case_id',$case_id);
            $data = $data->get()->first();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getRatingsByCaseId($case_id){
        try {
            DB::beginTransaction();
            $data = DB::table('case_ratings')->where('case_id',$case_id)->avg('rating');
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getNotification($user_id){
        try {
            DB::beginTransaction();
            $data = DB::table('notification')->where('user_id',$user_id)->whereIn('type',['document','agreement'])->where('status','Active')->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getCaseByCaseid($case_id){
        try {
            DB::beginTransaction();
            $data = DB::table('cases')->addSelect('cases.*', 'flight_details.flight_name', 'flight_details.flight_number')
                ->leftJoin('flight_details', 'cases.flight_relation_id', '=', 'flight_details.flight_relation_id');
            $data->where('cases.case_id',$case_id);
            $data = $data->get()->first();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            echo $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getPassportByCaseID($case_id){
        try {
            DB::beginTransaction();
            $data = DB::table('passenger_passport')->where('case_id',$case_id)->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getAccountDetailsByCaseId($case_id){
        try {
            DB::beginTransaction();
            $data = DB::table('passenger_account_details')->where('case_id',$case_id)->get();
            DB::commit();
            return $data->first();
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }
    public function getPassengerDocumentsByCaseId($case_id){
        try {
            DB::beginTransaction();
            $data = DB::table('passenger_passport')->where('passenger_passport.case_id',$case_id)
            ->select('passenger_passport.*','passenger.first_name','passenger.last_name')
            ->join('passenger','passenger.case_id','passenger_passport.case_id')
            ->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
        
    }
    
    public function caseStatusByCaseId($case_id){
        try {
            DB::beginTransaction();
            $data = DB::table('case_progress_status')->where('case_id',$case_id)->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
        
    }

    public function getAllcaseUserIDForCase($user_id){
        try {
            DB::beginTransaction();
            $data = DB::table('cases')->addSelect('cases.*', 'flight_details.flight_name', 'flight_details.flight_number')
            ->leftJoin('flight_details', 'cases.flight_relation_id', '=', 'flight_details.flight_relation_id')->where('cases.user_id',$user_id)
            ->whereIn('cases.case_status',['new', 'ongoing', 'accepted', 'rejected'])->where('cases.status','=','Active')->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function updatepowerofAttorneyOrPaymentAggreementUpdate($case_id,$temp,$msg,$statusmsg){
        try {
            DB::beginTransaction();
            DB::table('cases')->where('case_id',$case_id)->update($temp);
            DB::table('case_progress_status')->insert(['status_message' => $msg,'case_status'=>$statusmsg,'case_id' =>$case_id]);
            DB::commit();
            return true;
        } catch (\Exception $e) {
            echo $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getExpenseDocumentImagesByFlightRelationId($flight_relation_id){
        try {
            DB::beginTransaction();
            $data = DB::table('expense_document');
            $data->where('flight_relation_id',$flight_relation_id);
            $data = $data->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function deleteExpenseImage($flight_relation_id){
        try {
            DB::beginTransaction();
            $data = DB::table('expense_document')->where('flight_realtion_id', '=', $flight_relation_id)->delete();;
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }
    //-----------------------------------------------Get Apis-----------------------------
    public function getPassengerByPassengerId($passenger_id){
        try {
            DB::beginTransaction();
            $data = DB::table('passenger')->where('passenger_id', '=', $passenger_id)->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }
    
     public function getPassportByUserID($user_id){
        try {
            DB::beginTransaction();
            $data = DB::table('passenger_passport')->select('passenger_passport.*','passenger.first_name','passenger.last_name')->where('passenger_passport.user_id',$user_id)
            ->join('passenger','passenger.passenger_id','passenger_passport.passenger_id')
            ->orderBy('passenger_passport.passenger_passport_id','desc')
            ->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getAccountDetailsByUserId($user_id){
        try {
            DB::beginTransaction();
            $data = DB::table('passenger_account_details')->where('user_id',$user_id)->get();
            DB::commit();
            return $data->first();
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
    }

    public function getPassengerDocumentsByUserID($user_id,$type,$case_id=null){
        try {
            DB::beginTransaction();
            $data = DB::table('passenger_documents')->where('user_id',$user_id)->where('document_type',$type);
            if(!empty($case_id)){
                $data->where('case_id',$case_id);
            }
            DB::commit();
            return $data->get();
        } catch (\Exception $e) {
            $e->getMessage();
            DB::rollback();
            return false;
        }
        
    }
    
    public function getPassengerByCaseID($case_id){
        try {
            DB::beginTransaction();
            $data = DB::table('passenger')
            ->addSelect('passenger.first_name','passenger.last_name','passenger_passport.passport_number','passenger_passport.passenger_id')
            ->leftjoin('passenger_passport','passenger_passport.passenger_id','passenger.passenger_id')
            ->where('passenger_passport.case_id',$case_id)->get();
            DB::commit();
            return $data;
        } catch (\Exception $e) {
            echo $e->getMessage();
            DB::rollback();
            return false;
        }
    }
    
   
    

}

