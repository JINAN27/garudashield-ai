<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class DashboardAuth
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! $request->session()->get('dashboard_authenticated')) {
            return redirect()->route('login');
        }
        return $next($request);
    }
}
