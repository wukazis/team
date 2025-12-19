// Live2D 看板娘初始化 - Miku 模型
(function () {
    if (screen.width < 768) return;

    const live2d_path = "https://fastly.jsdelivr.net/gh/stevenjoezhang/live2d-widget@latest/";
    const miku_model = "https://unpkg.com/live2d-widget-model-miku@1.0.5/assets/miku.model.json";

    function loadResource(url, type) {
        return new Promise((resolve, reject) => {
            let el;
            if (type === "css") {
                el = document.createElement("link");
                el.rel = "stylesheet";
                el.href = url;
            } else {
                el = document.createElement("script");
                el.src = url;
            }
            el.onload = resolve;
            el.onerror = reject;
            document.head.appendChild(el);
        });
    }

    Promise.all([
        loadResource(live2d_path + "waifu.css", "css"),
        loadResource(live2d_path + "live2d.min.js", "js")
    ]).then(() => {
        // 创建 canvas
        const canvas = document.createElement("canvas");
        canvas.id = "live2d";
        canvas.width = 280;
        canvas.height = 250;
        canvas.style.cssText = "position:fixed;bottom:0;left:0;z-index:999;pointer-events:none;";
        document.body.appendChild(canvas);

        // 加载模型
        const model = new ModelSettingJson();
        fetch(miku_model)
            .then(res => res.json())
            .then(json => {
                const baseUrl = miku_model.substring(0, miku_model.lastIndexOf("/") + 1);
                loadlive2d("live2d", miku_model);
            });
    });
})();
