package mav

fun main() {
    val loadTest = LoadTest()

    loadTest.exec(
        "http://ec2-52-90-132-237.compute-1.amazonaws.com:8080/key-exchange",
        "http://ec2-52-90-132-237.compute-1.amazonaws.com:8080/wiremock/api/github/users/octocat",
        "wasabi-man",
        "{\"age\":30,\"name\":\"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum facilisis mauris tellus, vel ultrices mauris viverra eget. Nunc posuere tortor a enim iaculis condimentum. Aliquam erat volutpat. Etiam porta purus non eros posuere, ac sollicitudin lectus tincidunt. Suspendisse iaculis interdum tortor id blandit. Aliquam in ex blandit, efficitur turpis vitae, malesuada enim. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed nec massa fermentum nunc tincidunt convallis a at purus. Nam scelerisque mi quis consequat condimentum. Quisque consequat, libero sed pellentesque convallis, massa turpis interd\"}",
        true,
        true
    )
}