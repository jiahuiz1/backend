import CSE230.Eval
import System.Environment (getArgs)

main :: IO ()
main = do 
  fs <- getArgs
  mapM_ runFile fs


