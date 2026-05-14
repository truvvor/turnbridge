package main

import (
    "fmt"
    mathrand "math/rand"
)

type Profile struct {
    UserAgent       string
    SecChUa         string
    SecChUaMobile   string
    SecChUaPlatform string
}


var firstNames = []string{
    "Александр", "Дмитрий", "Максим", "Сергей", "Андрей", "Алексей", "Артём", "Илья",
    "Кирилл", "Михаил", "Никита", "Матвей", "Роман", "Егор", "Арсений", "Иван",
    "Денис", "Даниил", "Тимофей", "Владислав", "Игорь", "Павел", "Руслан", "Марк",
    "Анна", "Мария", "Елена", "Дарья", "Анастасия", "Екатерина", "Виктория", "Ольга",
    "Наталья", "Юлия", "Татьяна", "Светлана", "Ирина", "Ксения", "Алина", "Елизавета",
}

var lastNames = []string{
    "Иванов", "Смирнов", "Кузнецов", "Попов", "Васильев", "Петров", "Соколов", "Михайлов",
    "Новиков", "Федоров", "Морозов", "Волков", "Алексеев", "Лебедев", "Семенов", "Егоров",
    "Павлов", "Козлов", "Степанов", "Николаев", "Орлов", "Андреев", "Макаров", "Никитин",
    "Захаров", "Зайцев", "Соловьев", "Борисов", "Яковлев", "Григорьев", "Романов", "Воробьев",
}

var profiles = []Profile{
    // iPhone Safari only. VK's anti-bot pipeline triggers the
    // "Confirm you're not a robot" checkbox when it sees a mismatch
    // between the connection (Russian cellular IP, iPhone-shaped TLS
    // fingerprint from NSURLSession's underlying CFNetwork stack)
    // and the User-Agent header. Real users clicking a VK call link
    // from Safari on iPhone aren't asked for a captcha — and that's
    // exactly the request we want to look like.
    //
    // Safari deliberately doesn't implement Client Hints; vk_captcha
    // skips the sec-ch-ua headers entirely when SecChUa is empty,
    // matching what mobile Safari actually sends on the wire.
    {
        UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/15E148 Safari/604.1",
    },
    {
        UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    },
    {
        UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    },
    {
        UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    },
    {
        UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    },
    {
        UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    },
}

func getRandomProfile() Profile {
    return profiles[mathrand.Intn(len(profiles))]
}

func generateName() string {
    if mathrand.Float32() < 0.3 {
        return firstNames[mathrand.Intn(len(firstNames))]
    }
    fn := firstNames[mathrand.Intn(len(firstNames))]
    ln := lastNames[mathrand.Intn(len(lastNames))]
    lastChar := fn[len(fn)-2:]
    if lastChar == "а" || lastChar == "я" {
        return fmt.Sprintf("%s %sа", fn, ln)
    }
    return fmt.Sprintf("%s %s", fn, ln)
}
