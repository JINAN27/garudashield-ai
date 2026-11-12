<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class SessionController extends Controller
{
    public function create() { return view('auth.login'); }

    public function store(Request $request)
    {
        $credentials = $request->validate(['username' => ['required', 'string', 'max:100'], 'password' => ['required', 'string', 'max:200']]);
        $username = (string) config('services.garudashield.username');
        $password = (string) config('services.garudashield.password');
        $valid = $password !== '' && hash_equals($username, $credentials['username']) && (str_starts_with($password, '$2y$') ? Hash::check($credentials['password'], $password) : hash_equals($password, $credentials['password']));
        if (! $valid) return back()->withErrors(['username' => 'Kredensial tidak valid atau akses dashboard belum dikonfigurasi.'])->onlyInput('username');

        $request->session()->regenerate();
        $request->session()->put('dashboard_authenticated', true);
        return redirect()->intended(route('dashboard'));
    }

    public function destroy(Request $request)
    {
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return redirect()->route('login');
    }
}
