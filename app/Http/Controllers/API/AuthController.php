<?php


namespace App\Http\Controllers\API;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use App\Http\Controllers\API\ApiController;
use Illuminate\Support\Facades\DB;
class AuthController extends ApiController
{
    public function login(Request $request)
    {
        if(Auth::attempt(['email' => $request->email, 'password' => $request->password])) { 
            $user = Auth::user(); 

            $response['token'] =  $user->createToken('sanctum')->plainTextToken; 
            $response['name'] =  $user->name;

            return $this->successResponse('User successfully logged-in.', $response);
        } 
        else { 
            return $this->errorResponse('Unauthorized.', ['error'=>'Unauthorized'], 403);
        } 
    }

    public function register(Request $request)
    {
        

        try {
            DB::beginTransaction();

            $validator = Validator::make($request->all(), [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required',
                'confirm_password' => 'required|same:password',
            ]);

            if ($validator->fails()) {
                return $this->errorResponse('Validation error.', $validator->errors(), 400);
            }

            $data = $request->all();
            $data['password'] = bcrypt($data['password']);

            $user = User::create($data);

            $response['token'] = $user->createToken('sanctum')->plainTextToken;
            $response['name'] = $user->name;

            DB::commit();

            return $this->successResponse('User created successfully.', $response);
        } catch (\Exception $e) {
            DB::rollback();
            return $this->errorResponse('Error occurred.', $e->getMessage(), 500);
        }

    }

    public function logout() 
    {
        auth()->user()->currentAccessToken()->delete();

        return $this->successResponse('Logout successfully.');
    }
}