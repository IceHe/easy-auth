import os

import uvicorn

from auth_service import bootstrap, create_app


bootstrap()
app = create_app()


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "8080")), reload=False)
