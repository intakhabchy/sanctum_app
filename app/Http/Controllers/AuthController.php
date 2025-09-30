<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request){
        $request->validate([
            'name' => 'required',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return response()->json([
            'success' => true,
            'message' => 'User created successfully'
        ]);
    }

    public function login(Request $request){

        $request->validate([
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:6',
        ]);

        if(!Auth::attempt($request->only('email','password'))){
            return response()->json([
                'status' => false,
                'message' => 'Unauthorized'
            ], 401);
        }

        $user = User::where('email',$request->email)->firstOrFail();

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => true,
            'token' => $token,
            'message' => 'Login Successful'
        ]);
    }

    public function logout(Request $request){
        $request->user()->currentAccessToken()->delete();
        
        return response()->json([
            'status' => true,
            'message' => 'Logout Successful !!!'
        ]);
    }
}
