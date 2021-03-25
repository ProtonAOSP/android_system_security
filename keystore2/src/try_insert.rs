// Copyright 2021, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The TryInsert trait adds to Option<T> the method
//! get_or_try_to_insert_with, which is analogous to
//! get_or_insert_with, but allows the called function to fail and propagates the failure.

/// The TryInsert trait adds to Option<T> the method
/// get_or_try_to_insert_with, which is analogous to
/// get_or_insert_with, but allows the called function to fail and propagates the failure.
pub trait TryInsert {
    /// Type of the Ok branch of the Result
    type Item;
    /// Inserts a value computed from `f` into the option if it is [`None`],
    /// then returns a mutable reference to the contained value. If `f`
    /// returns Err, the Option is unchanged.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut x = None;
    /// assert_eq!(x.get_or_try_to_insert_with(Err("oops".to_string())), Err("oops".to_string()))
    /// {
    ///     let y: &mut u32 = x.get_or_try_to_insert_with(|| Ok(5))?;
    ///     assert_eq!(y, &5);
    ///
    ///     *y = 7;
    /// }
    ///
    /// assert_eq!(x, Some(7));
    /// ```
    fn get_or_try_to_insert_with<E, F: FnOnce() -> Result<Self::Item, E>>(
        &mut self,
        f: F,
    ) -> Result<&mut Self::Item, E>;
}

impl<T> TryInsert for Option<T> {
    type Item = T;
    fn get_or_try_to_insert_with<E, F: FnOnce() -> Result<Self::Item, E>>(
        &mut self,
        f: F,
    ) -> Result<&mut Self::Item, E> {
        if self.is_none() {
            *self = Some(f()?);
        }

        match self {
            Some(v) => Ok(v),
            // SAFETY: a `None` variant for `self` would have been replaced by a `Some`
            // variant in the code above.
            None => unsafe { std::hint::unreachable_unchecked() },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn fails() -> Result<i32, String> {
        Err("fail".to_string())
    }

    fn succeeds() -> Result<i32, String> {
        Ok(99)
    }

    #[test]
    fn test() {
        let mut x = None;
        assert_eq!(x.get_or_try_to_insert_with(fails), Err("fail".to_string()));
        assert_eq!(x, None);
        assert_eq!(*x.get_or_try_to_insert_with(succeeds).unwrap(), 99);
        assert_eq!(x, Some(99));
        x = Some(42);
        assert_eq!(*x.get_or_try_to_insert_with(fails).unwrap(), 42);
        assert_eq!(x, Some(42));
        assert_eq!(*x.get_or_try_to_insert_with(succeeds).unwrap(), 42);
        assert_eq!(x, Some(42));
        *x.get_or_try_to_insert_with(fails).unwrap() = 2;
        assert_eq!(x, Some(2));
        *x.get_or_try_to_insert_with(succeeds).unwrap() = 3;
        assert_eq!(x, Some(3));
        x = None;
        *x.get_or_try_to_insert_with(succeeds).unwrap() = 5;
        assert_eq!(x, Some(5));
    }
}
