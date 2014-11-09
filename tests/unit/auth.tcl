start_server {tags {"auth"}} {
    test {AUTH fails if there is no password configured server side} {
        catch {r auth foo} err
        set _ $err
    } {ERR*no password*}
}

start_server {tags {"auth"} overrides {requirepass foobar}} {
    test {AUTH fails when a wrong password is given} {
        catch {r auth wrong!} err
        set _ $err
    } {ERR*invalid password}

    test {Arbitrary command gives an error when AUTH is required} {
        catch {r set foo bar} err
        set _ $err
    } {NOAUTH*}

    test {AUTH succeeds when the right password is given} {
        r auth foobar
    } {OK}

    test {Once AUTH succeeded we can actually send commands to the server} {
        r set foo 100
        r incr foo
    } {101}
}

start_server {tags {"auth"} overrides {requirepass2 foobar}} {
    test {AUTH fails when a wrong password is given} {
        catch {r auth wrong!} err
        set _ $err
    } {ERR*invalid password}

    test {Arbitrary command gives an error when AUTH is required} {
        catch {r set foo bar} err
        set _ $err
    } {NOAUTH*}

    test {AUTH succeeds when the right password is given} {
        r auth foobar
    } {OK}

    test {Once AUTH succeeded we can actually send commands to the server} {
        r set foo 100
        r incr foo
    } {101}
}

start_server {tags {"auth"} overrides {requirepass {foobar} requirepass2 {foobar}}} {
    test {AUTH fails when a wrong password is given} {
        catch {r auth wrong!} err
        set _ $err
    } {ERR*invalid password}

    test {Arbitrary command gives an error when AUTH is required} {
        catch {r set foo bar} err
        set _ $err
    } {NOAUTH*}

    test {AUTH succeeds when the right password is given} {
        r auth foobar
    } {OK}

    test {Once AUTH succeeded we can actually send commands to the server} {
        r set foo 100
        r incr foo
    } {101}
}

start_server {tags {"auth"} overrides {requirepass {foo} requirepass2 {bar}}} {
    test {AUTH fails when a wrong password is given} {
        catch {r auth wrong!} err
        set _ $err
    } {ERR*invalid password}

    test {Arbitrary command gives an error when AUTH is required} {
        catch {r set foo bar} err
        set _ $err
    } {NOAUTH*}

    test {AUTH succeeds when the right password is given (requirepass)} {
        r auth foo
    } {OK}

    test {Once AUTH succeeded we can actually send commands to the server (requirepass)} {
        r set foo 100
        r incr foo
    } {101}

    test {AUTH succeeds when the right password is given (requirepass2)} {
        r auth bar
    } {OK}

    test {Once AUTH succeeded we can actually send commands to the server (requirepass2)} {
        r set foo 100
        r incr foo
    } {101}
}
