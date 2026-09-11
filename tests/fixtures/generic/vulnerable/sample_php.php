<?php
// @audit-fixture
// @rule: sql_injection_concat_php, command_injection_php, eval_injection_php,
//        unsafe_deserialization_php, file_inclusion_php, xxe_injection_php,
//        xss_echo_php, xss_blade_unescaped, weak_crypto_php, weak_random_php,
//        open_redirect_php, extract_usage_php, type_juggling_php,
//        mass_assignment_laravel, verbose_exception_php, secret_logged_php,
//        db_logic_controller_php, error_suppressor_php, catch_all_exception_php
// @category: security, architecture, maintenance
// @expected: detected

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

class VulnerableController extends Controller
{
    // SQL injection par concatenation
    public function findUser($username)
    {
        $result = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $username . "'");
    }

    // Command injection
    public function runCommand(Request $request)
    {
        $output = shell_exec($request->input('cmd'));
    }

    // Eval injection
    public function evaluate(Request $request)
    {
        eval($request->input('code'));
    }

    // Unsafe deserialization
    public function loadData($data)
    {
        $obj = unserialize($data);
    }

    // File inclusion
    public function loadTemplate(Request $request)
    {
        include($request->input('template'));
    }

    // XXE injection
    public function parseXml($xml)
    {
        $doc = simplexml_load_string($xml);
    }

    // XSS echo
    public function showName()
    {
        echo $_GET['name'];
    }

    // Weak crypto
    public function hashPassword($password)
    {
        return md5($password);
    }

    // Weak random
    public function generateToken()
    {
        return 'token_' . mt_rand();
    }

    // Open redirect
    public function login(Request $request)
    {
        header("Location: " . $_GET['redirect']);
    }

    // Extract usage
    public function processForm()
    {
        extract($_POST);
    }

    // Type juggling
    public function checkToken($input, $stored)
    {
        if ($input == $stored) {
            return true;
        }
    }

    // Mass assignment
    public function store(Request $request)
    {
        User::create($request->all());
    }

    // Verbose exception (var_dump)
    public function debug()
    {
        var_dump(debug_backtrace());
    }

    // Secret logged
    public function authenticate($password)
    {
        Log::info("Auth attempt with password: " . $password);
    }

    // DB logic in controller
    public function getUsers()
    {
        return DB::table('users')->where('active', 1)->get();
    }

    // Error suppressor
    public function readFile($path)
    {
        $data = @file_get_contents($path);
    }

    // Blade unescaped output (XSS)
    public function renderBlade()
    {
        return view('profile', ['bio' => '{!! $user->bio !!}']);
    }

    // Laravel whereRaw SQL injection
    public function searchUsers(Request $request)
    {
        return User::whereRaw("name = '" . $request->input('name') . "'")->get();
    }

    // WordPress wpdb injection
    public function wpSearch($name)
    {
        global $wpdb;
        $results = $wpdb->get_results("SELECT * FROM wp_users WHERE name = '" . $name . "'");
    }

    // Doctrine DQL injection
    public function findByName($name)
    {
        $dql = $entityManager->createQuery("SELECT u FROM User u WHERE u.name = '" . $name . "'");
    }

    // Generic catch
    public function processData()
    {
        try {
            $this->riskyOperation();
        } catch (\Exception $e) {
            echo $e->getMessage();
        }
    }
}
